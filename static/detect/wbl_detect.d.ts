/* tslint:disable */
/* eslint-disable */

/**
 * t109 = ReportSession
 */
export class ReportSession {
    free(): void;
    [Symbol.dispose](): void;
    /**
     * Apply an enrichment overlay built in JS:
     * `{ "1.2.3.4": { "rdns": "...", "org": "...", "org_country": "..." }, ... }`
     * Missing keys keep their old values; missing IPs are ignored.
     */
    applyEnrichment(json: string): void;
    /**
     * JSON-string list of IPv4 addresses the browser should DoH+RDAP for.
     * IPv6 is intentionally excluded in v0 — the reverse zone is its own
     * beast and a partial result is better than blocking the report.
     */
    ipsToEnrich(): any;
    /**
     * Returns `Err(JsValue)` when the input is empty or larger than
     * `MAX_INPUT_BYTES`. JS sees a normal thrown error and can render a
     * friendly message instead of a blank tab.
     */
    constructor(text: string, source_label: string);
    /**
     * Render the full standalone HTML report — what the user downloads.
     */
    renderHtml(): string;
    /**
     * Small JSON blob the loading UI displays (parsed/skipped count,
     * detected format, class breakdown). No customer-data leakage; safe
     * to log to the page.
     */
    stats(): any;
}

export function _start(): void;

export function classify_rows(text: string, max_rows: number): any;

export function detect(text: string, max_rows: number): any;

/**
 * Canonical surface-area probe list — `{path, label, sev}` objects.
 * The `/scan` page calls this once at startup so the browser drives its
 * own probe list without a separate hard-coded JS array.
 *
 * f406 = get_probes
 */
export function getProbes(): any;

/**
 * One-shot fast path: parse + aggregate + render with no enrichment.
 * Used by `/try` to paint a first report instantly while the JS layer
 * kicks off DoH + RDAP in parallel.
 */
export function renderReport(text: string, source_label: string): string;

export type InitInput = RequestInfo | URL | Response | BufferSource | WebAssembly.Module;

export interface InitOutput {
    readonly memory: WebAssembly.Memory;
    readonly __wbg_reportsession_free: (a: number, b: number) => void;
    readonly _start: () => void;
    readonly classify_rows: (a: number, b: number, c: number, d: number) => void;
    readonly detect: (a: number, b: number, c: number, d: number) => void;
    readonly getProbes: (a: number) => void;
    readonly renderReport: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly reportsession_applyEnrichment: (a: number, b: number, c: number, d: number) => void;
    readonly reportsession_ipsToEnrich: (a: number, b: number) => void;
    readonly reportsession_new: (a: number, b: number, c: number, d: number, e: number) => void;
    readonly reportsession_renderHtml: (a: number, b: number) => void;
    readonly reportsession_stats: (a: number, b: number) => void;
    readonly __wbindgen_export: (a: number, b: number) => number;
    readonly __wbindgen_export2: (a: number, b: number, c: number, d: number) => number;
    readonly __wbindgen_export3: (a: number) => void;
    readonly __wbindgen_add_to_stack_pointer: (a: number) => number;
    readonly __wbindgen_export4: (a: number, b: number, c: number) => void;
    readonly __wbindgen_start: () => void;
}

export type SyncInitInput = BufferSource | WebAssembly.Module;

/**
 * Instantiates the given `module`, which can either be bytes or
 * a precompiled `WebAssembly.Module`.
 *
 * @param {{ module: SyncInitInput }} module - Passing `SyncInitInput` directly is deprecated.
 *
 * @returns {InitOutput}
 */
export function initSync(module: { module: SyncInitInput } | SyncInitInput): InitOutput;

/**
 * If `module_or_path` is {RequestInfo} or {URL}, makes a request and
 * for everything else, calls `WebAssembly.instantiate` directly.
 *
 * @param {{ module_or_path: InitInput | Promise<InitInput> }} module_or_path - Passing `InitInput` directly is deprecated.
 *
 * @returns {Promise<InitOutput>}
 */
export default function __wbg_init (module_or_path?: { module_or_path: InitInput | Promise<InitInput> } | InitInput | Promise<InitInput>): Promise<InitOutput>;
