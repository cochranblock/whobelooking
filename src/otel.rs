// Unlicense — public domain — whobelooking.org
//! OpenTelemetry init and metric instruments. Compiled only when the `otel`
//! feature is enabled — operators who don't run a collector pay zero
//! binary-size cost.
//!
//! Environment configuration follows the standard OTEL SDK contract so
//! existing observability tooling Just Works without per-app config:
//!
//!   * `OTEL_EXPORTER_OTLP_ENDPOINT` — collector URL (default `http://localhost:4317` gRPC)
//!   * `OTEL_SERVICE_NAME`           — service identifier (default `whobelooking`)
//!   * `OTEL_RESOURCE_ATTRIBUTES`    — `key=value,key=value` passthrough
//!
//! When the feature is OFF, the [`init`] function returns a no-op `Guard`
//! so call-sites in `main.rs` stay clean.
//!
//! The metric instruments live in [`metrics::Instruments`] — a singleton
//! cached via `OnceLock` so handler hot paths don't re-lookup. Counters
//! land at `wbl.enrichment.snapshot.rebuilds`, etc.
//! Histograms use OTEL semantic-convention units (`ms`, `By`).

#[cfg(feature = "otel")]
use opentelemetry::KeyValue;
#[cfg(feature = "otel")]
use opentelemetry::global;
#[cfg(feature = "otel")]
use opentelemetry::metrics::{Counter, Histogram};
#[cfg(feature = "otel")]
use opentelemetry_otlp::WithExportConfig;
#[cfg(feature = "otel")]
use opentelemetry_sdk::Resource;
#[cfg(feature = "otel")]
use std::sync::OnceLock;

/// Guard that keeps the SDK providers alive for the lifetime of the
/// process. Dropping it flushes pending spans + metrics and shuts down
/// the OTLP exporter. `main.rs` holds it until the server returns.
pub struct Guard {
    #[cfg(feature = "otel")]
    _tracer_provider: opentelemetry_sdk::trace::TracerProvider,
    #[cfg(feature = "otel")]
    _meter_provider: opentelemetry_sdk::metrics::SdkMeterProvider,
}

impl Drop for Guard {
    fn drop(&mut self) {
        #[cfg(feature = "otel")]
        {
            // Best-effort flush; failure here is non-fatal — the process
            // is exiting anyway. Log to stderr so the operator sees if
            // the collector was unreachable during shutdown.
            if let Err(e) = self._tracer_provider.shutdown() {
                eprintln!("otel: tracer shutdown error: {:?}", e);
            }
            if let Err(e) = self._meter_provider.shutdown() {
                eprintln!("otel: meter shutdown error: {:?}", e);
            }
        }
    }
}

/// Initialize OTEL providers and wire them into the global registry.
/// Idempotent — calling twice is a no-op on the second call.
///
/// Returns `Ok(Guard)` on success. When the `otel` feature is disabled
/// this is the no-op variant; the binary builds and runs identically
/// regardless of the feature flag at the call site.
#[allow(unused_variables)]
pub fn init(default_service: &str) -> anyhow::Result<Guard> {
    #[cfg(not(feature = "otel"))]
    {
        // No-op when the feature is off — keep the call-site API stable.
        Ok(Guard {})
    }

    #[cfg(feature = "otel")]
    {
        use opentelemetry_otlp::SpanExporter;

        let endpoint = std::env::var("OTEL_EXPORTER_OTLP_ENDPOINT")
            .unwrap_or_else(|_| "http://localhost:4317".to_string());
        let service_name =
            std::env::var("OTEL_SERVICE_NAME").unwrap_or_else(|_| default_service.to_string());

        // Resource: service.name + service.version + any env-injected
        // attributes the operator wants on every signal.
        let mut resource_attrs = vec![
            KeyValue::new(
                opentelemetry_semantic_conventions::resource::SERVICE_NAME,
                service_name.clone(),
            ),
            KeyValue::new(
                opentelemetry_semantic_conventions::resource::SERVICE_VERSION,
                env!("CARGO_PKG_VERSION"),
            ),
        ];
        if let Ok(extra) = std::env::var("OTEL_RESOURCE_ATTRIBUTES") {
            for pair in extra.split(',') {
                if let Some((k, v)) = pair.split_once('=') {
                    resource_attrs.push(KeyValue::new(k.trim().to_string(), v.trim().to_string()));
                }
            }
        }
        let resource = Resource::new(resource_attrs);

        // Trace exporter — OTLP/gRPC.
        let span_exporter = SpanExporter::builder()
            .with_tonic()
            .with_endpoint(&endpoint)
            .build()?;
        let tracer_provider = opentelemetry_sdk::trace::TracerProvider::builder()
            .with_resource(resource.clone())
            .with_batch_exporter(span_exporter, opentelemetry_sdk::runtime::Tokio)
            .build();
        global::set_tracer_provider(tracer_provider.clone());

        // Metric exporter — OTLP/gRPC.
        let metric_exporter = opentelemetry_otlp::MetricExporter::builder()
            .with_tonic()
            .with_endpoint(&endpoint)
            .build()?;
        let reader = opentelemetry_sdk::metrics::PeriodicReader::builder(
            metric_exporter,
            opentelemetry_sdk::runtime::Tokio,
        )
        .build();
        let meter_provider = opentelemetry_sdk::metrics::SdkMeterProvider::builder()
            .with_resource(resource)
            .with_reader(reader)
            .build();
        global::set_meter_provider(meter_provider.clone());

        // Eagerly initialize the instrument cache so the first handler
        // hit doesn't pay the lookup cost.
        let _ = metrics::instruments();

        Ok(Guard {
            _tracer_provider: tracer_provider,
            _meter_provider: meter_provider,
        })
    }
}

#[cfg(feature = "otel")]
pub mod metrics {
    //! Lazy-init metric instruments. Handlers grab `instruments()` and
    //! call counter/histogram add() methods directly — no per-call lookup.

    use super::*;

    /// Cached set of all the instruments we record from across the binary.
    /// The `&'static` lifetime comes from `OnceLock<Instruments>`.
    ///
    /// RDAP cache hits/misses aren't here because the server doesn't run
    /// RDAP — that happens in the browser via JS on `/try`. If we add a
    /// server-side RDAP proxy mode later, re-add `rdap_cache_hits` /
    /// `rdap_cache_misses` counters at that point.
    pub struct Instruments {
        /// `wbl.enrichment.snapshot.rebuilds` — `/api/enrichment.json` rebuild events.
        pub enrichment_rebuilds: Counter<u64>,
        /// `wbl.enrichment.snapshot.entries` — entry count at last rebuild.
        pub enrichment_entries: Histogram<u64>,
    }

    static INSTRUMENTS: OnceLock<Instruments> = OnceLock::new();

    pub fn instruments() -> &'static Instruments {
        INSTRUMENTS.get_or_init(|| {
            let meter = global::meter("whobelooking");
            Instruments {
                enrichment_rebuilds: meter
                    .u64_counter("wbl.enrichment.snapshot.rebuilds")
                    .with_description("/api/enrichment.json snapshot rebuilds")
                    .build(),
                enrichment_entries: meter
                    .u64_histogram("wbl.enrichment.snapshot.entries")
                    .with_description("Entries in the snapshot at rebuild time")
                    .build(),
            }
        })
    }
}

// No-op shim for non-otel builds — keeps call-sites free of `#[cfg]`.
//
// Every method here mirrors the real `Instruments` API but does nothing.
// Callers use e.g. `otel::metrics::instruments().enrichment_rebuilt(n)`
// without needing to know whether OTEL is compiled in.
#[cfg(not(feature = "otel"))]
pub mod metrics {
    /// Stub matching the real `Instruments` API. Call-sites use a unified
    /// `&[(&str, &str)]` attribute slice regardless of the feature flag,
    /// so the shim and the real impl have byte-identical signatures.
    pub struct Instruments;
    impl Instruments {
        #[inline]
        pub fn enrichment_rebuilt(&self, _entries: u64) {}
    }
    static I: Instruments = Instruments;
    pub fn instruments() -> &'static Instruments {
        &I
    }
}

// Same method surface, real impl. The OTEL crate's `KeyValue` lands here.
#[cfg(feature = "otel")]
impl metrics::Instruments {
    #[inline]
    pub fn enrichment_rebuilt(&self, entries: u64) {
        self.enrichment_rebuilds.add(1, &[]);
        self.enrichment_entries.record(entries, &[]);
    }
}
