YAML configurable command line tool for parsing Nessus files. Nessus findings are parsed using patterns and organised into high-level categories containing the host, port and service. This tool is intended to speed up analysis and reporting of vulnerability scanning data.

Example output and help output shown below.

```
----- Apache - Multiple Vulnerabilities -----
127.0.0.1:80/tcp/www
127.0.0.1:443/tcp/www
```

```
Usage: main --nessus=STRING [flags]

Process and filter Nessus reports.

Patterns can be specified in two ways: 1. Command line using --pattern flag 2. YAML file using --pattern-file flag

Command line pattern format: expression::title::type::options - expression: The search pattern - title: Display title (optional) - type: simple, regex, or glob (optional) - options: Comma-separated options
(optional):
  - case: Enable case sensitivity
  - inverse: Invert the match
  - fields=field1+field2: Specify fields to search

YAML file format example:

    patterns:
      - pattern:
          expression: "ssl"
          title: "SSL Issues"
          type: "regex"
          case_sensitive: false
          inverse: false
          fields: ["plugin_output", "pluginName", "description"]

Examples:

    # Using command line pattern. Expect nessus to be lowercase and contain the .nessus extension.
    goNessus --nessus=report.nessus --pattern="CVE-\\d+::CVE Findings::regex"

    # Using multiple .nessus files
    goNessus --nessus=report1.nessus,report2.nessus --pattern="CVE-\\d+::CVE Findings::regex"

    # Using pattern file
    goNessus --nessus=report.nessus --pattern-file=patterns.yml

    # Using both
    goNessus --nessus=report.nessus --pattern-file=patterns.yml --pattern="SQL*::SQL Issues::glob"

    # Optionally, ignore the 5GB file size limit
    goNessus --nessus=report.nessus --pattern-file=patterns.yml --pattern-file=patterns.yml --ignore-max-size"

Flags:
  -h, --help                   Show context-sensitive help.
      --nessus=STRING          .nessus XML NessusReport
      --pattern=PATTERN,...    Search patterns in format 'expression::title::type::options'. Multiple patterns allowed.
      --pattern-file=STRING    YAML file containing patterns
      --csv-only               Output .nessus direct to CSV.
      --output=STRING          Output folder (defaults to stdout)
      --ignore-max-size        Ignore max Nessus file size (5GB)
```