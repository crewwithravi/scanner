# Security Vulnerability Report

## 1. Executive Summary
A scan of the project dependencies identified a total of **11 vulnerabilities** across **7 dependencies**. The most critical findings involve **High** severity issues in `protobuf-java` (Denial of Service), `grpc-netty-shaded` (HTTP/2 DDoS), and `netty-handler` (Native Crash). Immediate action is recommended to upgrade these components to their patched versions.

## 2. Build System
- **System**: Gradle

## 3. Scan Statistics
- **Total Dependencies Checked**: 232
- **Vulnerable Dependencies**: 7
- **Safe Dependencies**: 225

## 4. Critical & High Vulnerabilities
| Dependency | Vuln ID | Severity | Summary | Fix Version |
| --- | --- | --- | --- | --- |
| com.google.protobuf:protobuf-java:3.25.3 | GHSA-735f-pc8j-v9w8 | HIGH | protobuf-java has potential Denial of Service issue | 3.25.5 |
| io.grpc:grpc-netty-shaded:1.62.2 | GHSA-prj3-ccx8-p6x4 | HIGH | Netty affected by MadeYouReset HTTP/2 DDoS vulnerability | 1.75.0 |
| io.netty:netty-handler:4.1.109.Final | GHSA-4g8c-wm8x-jfhw | HIGH | SslHandler doesn't correctly validate packets which can lead to native crash | 4.1.118.Final |

## 5. Medium & Low Vulnerabilities
| Dependency | Vuln ID | Severity | Summary | Fix Version |
| --- | --- | --- | --- | --- |
| com.google.guava:guava:30.1.1-android | GHSA-7g45-4rm6-3mm3 | MEDIUM | Guava vulnerable to insecure use of temporary directory | 32.0.0-android |
| com.google.guava:guava:30.1.1-android | GHSA-5mg8-w23w-74h3 | LOW | Information Disclosure in Guava | 32.0.0-android |
| com.google.guava:guava:29.0-android | GHSA-7g45-4rm6-3mm3 | MEDIUM | Guava vulnerable to insecure use of temporary directory | 32.0.0-android |
| com.google.guava:guava:29.0-android | GHSA-5mg8-w23w-74h3 | LOW | Information Disclosure in Guava | 32.0.0-android |
| com.google.guava:guava:31.1-android | GHSA-7g45-4rm6-3mm3 | MEDIUM | Guava vulnerable to insecure use of temporary directory | 32.0.0-android |
| com.google.guava:guava:31.1-android | GHSA-5mg8-w23w-74h3 | LOW | Information Disclosure in Guava | 32.0.0-android |
| io.netty:netty-codec-http:4.1.109.Final | GHSA-84h7-rjj3-6jx4 | LOW | Netty has a CRLF Injection vulnerability in HttpRequestEncoder | 4.2.8.Final |
| io.netty:netty-codec-http:4.1.109.Final | GHSA-fghv-69vj-qj49 | LOW | Netty vulnerable to request smuggling due to incorrect parsing of chunk extensions | 4.1.125.Final |

## 6. Upgrade Plan
| Dependency | Upgrade | Reason | Fix Version |
| --- | --- | --- | --- |
| com.google.guava:guava:30.1.1-android | com.google.guava:guava:30.1.1-android -> com.google.guava:guava:33.4.0-jre | Latest safe release fixing multiple CVEs; switching to JRE variant for server-side | 33.4.0-jre |
| com.google.guava:guava:29.0-android | com.google.guava:guava:29.0-android -> com.google.guava:guava:33.4.0-jre | Latest safe release fixing multiple CVEs; switching to JRE variant for server-side | 33.4.0-jre |
| com.google.guava:guava:31.1-android | com.google.guava:guava:31.1-android -> com.google.guava:guava:33.4.0-jre | Latest safe release fixing multiple CVEs; switching to JRE variant for server-side | 33.4.0-jre |
| com.google.protobuf:protobuf-java:3.25.3 | com.google.protobuf:protobuf-java:3.25.3 -> com.google.protobuf:protobuf-java:3.25.5 | Patched release fixing GHSA-735f-pc8j-v9w8; same major version | 3.25.5 |
| io.grpc:grpc-netty-shaded:1.62.2 | io.grpc:grpc-netty-shaded:1.62.2 -> io.grpc:grpc-netty-shaded:1.75.0 | Latest safe release fixing GHSA-prj3-ccx8-p6x4 | 1.75.0 |
| io.netty:netty-codec-http:4.1.109.Final | io.netty:netty-codec-http:4.1.109.Final -> io.netty:netty-codec-http:4.1.129.Final | Latest safe release fixing CRLF and smuggling issues | 4.1.129.Final |
| io.netty:netty-handler:4.1.109.Final | io.netty:netty-handler:4.1.109.Final -> io.netty:netty-handler:4.1.129.Final | Latest safe release fixing GHSA-4g8c-wm8x-jfhw | 4.1.129.Final |

## 7. Compatibility Analysis
| Dependency | Upgrade | Breaking Changes | Project Affected | Safe to Upgrade |
| --- | --- | --- | --- | --- |
| com.google.guava:guava:30.1.1-android | -> 33.4.0-jre | Removed @Beta from some APIs; deprecated Charsets constants. | No direct usage found in project source. | YES - Transitive dependency; JRE variant preferred for Spring Boot. |
| com.google.guava:guava:29.0-android | -> 33.4.0-jre | Removed @Beta from some APIs; deprecated Charsets constants. | No direct usage found in project source. | YES - Transitive dependency; JRE variant preferred for Spring Boot. |
| com.google.guava:guava:31.1-android | -> 33.4.0-jre | Removed @Beta from some APIs; deprecated Charsets constants. | No direct usage found in project source. | YES - Transitive dependency; JRE variant preferred for Spring Boot. |
| com.google.protobuf:protobuf-java:3.25.3 | -> 3.25.5 | None reported; patch release. | No direct usage found in project source. | YES - Backward compatible patch. |
| io.grpc:grpc-netty-shaded:1.62.2 | -> 1.75.0 | None reported; regular maintenance release. | No direct usage found in project source. | YES - Standard upgrade path. |
| io.netty:netty-codec-http:4.1.109.Final | -> 4.1.129.Final | None; binary compatible within 4.1.x series. | No direct usage found in project source. | YES - Critical security fix. |
| io.netty:netty-handler:4.1.109.Final | -> 4.1.129.Final | None; binary compatible within 4.1.x series. | No direct usage found in project source. | YES - Critical security fix. |

## 8. Compatibility Warnings
- **Guava Variant Switch**: The upgrade plan recommends switching from the `android` variant to the `jre` variant of Guava (`33.4.0-jre`). This is standard for server-side Java applications (like Spring Boot) and provides better performance and Java 8+ API compatibility.
- **Netty Alignment**: Ensure all `io.netty` dependencies are upgraded to the same version (`4.1.129.Final`) to avoid classpath conflicts, as Netty modules are tightly coupled.

## 9. Next Steps
1.  **Update `build.gradle`**: Apply the recommended versions.
2.  **Force Resolution**: Since many of these are transitive, use Gradle's resolution strategy to enforce the new versions:
    ```groovy
    configurations.all {
        resolutionStrategy.force 'com.google.guava:guava:33.4.0-jre'
        resolutionStrategy.force 'com.google.protobuf:protobuf-java:3.25.5'
        resolutionStrategy.force 'io.grpc:grpc-netty-shaded:1.75.0'
        resolutionStrategy.eachDependency { DependencyResolveDetails details ->
            if (details.requested.group == 'io.netty') {
                details.useVersion '4.1.129.Final'
            }
        }
    }
    ```
3.  **Run Tests**: Execute `./gradlew test` to verify application stability.
4.  **Rescan**: Run the security scanner again to confirm zero vulnerabilities.

## 10. Dependency Allowlist
Dependency Allowlist: ["com.google.guava:guava:30.1.1-android", "com.google.guava:guava:29.0-android", "com.google.guava:guava:31.1-android", "com.google.protobuf:protobuf-java:3.25.3", "io.grpc:grpc-netty-shaded:1.62.2", "io.netty:netty-codec-http:4.1.109.Final", "io.netty:netty-handler:4.1.109.Final"]
