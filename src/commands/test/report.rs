// machine-readable results of a test run, written with `--report <path>` so
// wrappers (unittest, pytest, CI) can show each case and why it failed
// without parsing the human output

use serde::Serialize;

#[derive(Debug, Clone, Serialize)]
pub struct CaseResult {
    pub name: String,
    pub passed: bool,
    /// why the case failed, as shown by --verbose
    pub reason: Option<String>,
}

#[derive(Debug, Clone, Serialize)]
pub struct SuiteReport {
    pub config: String,
    pub ruleset: String,
    pub tests: Vec<CaseResult>,
}

#[derive(Debug, Serialize)]
pub struct Report {
    pub total: usize,
    pub passed: usize,
    pub failed: usize,
    pub suites: Vec<SuiteReport>,
}

impl Report {
    /// tally passed and failed cases across every suite
    pub fn new(suites: Vec<SuiteReport>) -> Self {
        let cases = || suites.iter().flat_map(|suite| &suite.tests);
        let total = cases().count();
        let passed = cases().filter(|case| case.passed).count();
        Report { total, passed, failed: total - passed, suites }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn case(name: &str, reason: Option<&str>) -> CaseResult {
        CaseResult {
            name: name.to_string(),
            passed: reason.is_none(),
            reason: reason.map(str::to_string),
        }
    }

    #[test]
    fn counts_cases_across_suites() {
        let report = Report::new(vec![
            SuiteReport { config: "a.toml".into(), ruleset: "a.nft".into(), tests: vec![case("ok", None), case("bad", Some("verdict accept, expected drop"))] },
            SuiteReport { config: "b.toml".into(), ruleset: "b.nft".into(), tests: vec![case("ok", None)] },
        ]);
        assert_eq!((report.total, report.passed, report.failed), (3, 2, 1));
    }

    #[test]
    fn json_carries_each_case_and_its_reason() {
        let report = Report::new(vec![SuiteReport {
            config: "a.toml".into(),
            ruleset: "a.nft".into(),
            tests: vec![case("bad", Some("verdict accept, expected drop"))],
        }]);
        let json: serde_json::Value = serde_json::to_value(&report).unwrap();
        assert_eq!(json["failed"], 1);
        assert_eq!(json["suites"][0]["tests"][0]["name"], "bad");
        assert_eq!(json["suites"][0]["tests"][0]["reason"], "verdict accept, expected drop");
    }
}
