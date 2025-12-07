use reqwest::header::HeaderMap;

pub struct WebFingerprint {
    pub name: &'static str,
    pub location: FingerprintLocation,
    pub keyword: &'static str,
}

pub enum FingerprintLocation {
    Body,
    Header,
}

pub const FINGERPRINTS: &[WebFingerprint] = &[
    WebFingerprint {
        name: "Shiro",
        location: FingerprintLocation::Header,
        keyword: "rememberMe=deleteMe",
    },
    WebFingerprint {
        name: "Shiro",
        location: FingerprintLocation::Header,
        keyword: "rememberMe",
    },
    WebFingerprint {
        name: "SpringBoot",
        location: FingerprintLocation::Body,
        keyword: "Whitelabel Error Page",
    },
    WebFingerprint {
        name: "Tomcat",
        location: FingerprintLocation::Body,
        keyword: "Apache Tomcat",
    },
    WebFingerprint {
        name: "Weblogic",
        location: FingerprintLocation::Body,
        keyword: "Error 404--Not Found",
    },
    WebFingerprint {
        name: "Weblogic",
        location: FingerprintLocation::Body,
        keyword: "/console/login/LoginForm.jsp",
    },
    WebFingerprint {
        name: "JBoss",
        location: FingerprintLocation::Body,
        keyword: "JBoss Application Server",
    },
    WebFingerprint {
        name: "Jenkins",
        location: FingerprintLocation::Header,
        keyword: "X-Jenkins",
    },
    WebFingerprint {
        name: "Jenkins",
        location: FingerprintLocation::Body,
        keyword: "Jenkins",
    },
    WebFingerprint {
        name: "GitLab",
        location: FingerprintLocation::Body,
        keyword: "GitLab",
    },
    WebFingerprint {
        name: "Nginx",
        location: FingerprintLocation::Header,
        keyword: "nginx",
    },
    WebFingerprint {
        name: "Nginx",
        location: FingerprintLocation::Body,
        keyword: "nginx",
    },
    WebFingerprint {
        name: "Apache",
        location: FingerprintLocation::Header,
        keyword: "Apache",
    },
    WebFingerprint {
        name: "PHP",
        location: FingerprintLocation::Header,
        keyword: "PHP",
    },
    WebFingerprint {
        name: "ThinkPHP",
        location: FingerprintLocation::Header,
        keyword: "ThinkPHP",
    },
    WebFingerprint {
        name: "SeeyonOA",
        location: FingerprintLocation::Body,
        keyword: "/seeyon/USER-DATA/IMAGES/LOGIN/LOGIN.GIF",
    },
    WebFingerprint {
        name: "SeeyonOA",
        location: FingerprintLocation::Body,
        keyword: "/seeyon/common/",
    },
    WebFingerprint {
        name: "Weaver-E-cology",
        location: FingerprintLocation::Header,
        keyword: "ecology_JSessionid",
    },
    WebFingerprint {
        name: "Weaver-E-cology",
        location: FingerprintLocation::Body,
        keyword: "/wui/theme/ecology8",
    },
    WebFingerprint {
        name: "Landray-OA",
        location: FingerprintLocation::Body,
        keyword: "sys/ui/extend/theme/default/style/icon.css",
    },
    WebFingerprint {
        name: "Ruijie",
        location: FingerprintLocation::Body,
        keyword: "Ruijie",
    },
    WebFingerprint {
        name: "Hikvision",
        location: FingerprintLocation::Body,
        keyword: "Hikvision",
    },
    WebFingerprint {
        name: "Huawei",
        location: FingerprintLocation::Body,
        keyword: "Huawei",
    },
];

pub fn detect(headers: &HeaderMap, body: &str) -> Vec<String> {
    let mut detected = Vec::new();
    let mut seen = std::collections::HashSet::new();

    for fp in FINGERPRINTS {
        if seen.contains(fp.name) {
            continue;
        }

        let matched = match fp.location {
            FingerprintLocation::Body => body.contains(fp.keyword),
            FingerprintLocation::Header => headers.iter().any(|(k, v)| {
                let k_str = k.as_str();
                let v_str = v.to_str().unwrap_or("");
                k_str.contains(fp.keyword) || v_str.contains(fp.keyword)
            }),
        };

        if matched {
            detected.push(fp.name.to_string());
            seen.insert(fp.name);
        }
    }

    detected
}
