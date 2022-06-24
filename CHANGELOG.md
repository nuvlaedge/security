# Changelog
## Unreleased
### Added
 - Refactored main script. Added a Security class to control module settings in a static 
way
 - Added entry-point script to reset memory consumption of python
### Changed
 - DB update process externalized to curl and gzip programs
## [1.2.1] - 2022-03-24
### Added 
 - Add org.opencontainers image labels
### Changed
## [1.2.0] - 2021-09-07
### Added 
 - CVE DB partitioning 
 - Delay on first scan 
 - memory optimizations
### Changed
## [1.1.0] - 2021-07-26
### Added 
 - release of memory after each nmap execution
### Changed
 - report telemetry via Agent API
## [1.0.3] - 2021-04-23
### Added 
 - changing license to GPL
### Changed
## [1.0.2] - 2021-03-24
### Added
### Changed
 - fix backward compatibility with env var
## [1.0.2] - 2021-02-09
### Added
### Changed
 - improved filtering of false positives
## [1.0.1] - 2021-01-26
### Added
### Changed
 - fix parsing of misformatted vulnerabilities
## [1.0.0] - 2021-01-05
### Added
### Changed
 - exclude NB agent api port scan
## [0.1.1] - 2020-12-09
        ### Added
        ### Changed
                  - fix ID parsing bug
## [0.1.0] - 2020-12-04
        ### Added 
                  - re-use persistend environment variables
        ### Changed
                  - minor bug fixes
                  - set default for NUVLA_ENDPOINT_INSECURE
## [0.0.2] - 2020-11-02
### Added 
- auto updates from online vulnerability DB 
- parameterization of scanning and updating intervals
### Changed
## [0.0.1] - 2020-10-22
### Added 
- periodic security scans based on Vulscan for CVE
