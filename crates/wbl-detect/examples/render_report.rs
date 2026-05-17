// quick one-shot: parse a log file and write the HTML report to stdout
fn main() {
    let path = std::env::args()
        .nth(1)
        .expect("usage: render_report <log-path>");
    let log = std::fs::read_to_string(&path).expect("read log");
    let parsed = wbl_detect::parse::f400(&log);
    let report = wbl_detect::aggregate::f401(&parsed.events);
    let html = wbl_detect::report::f405(&report, &path);
    print!("{html}");
}
