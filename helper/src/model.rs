// Plain data shared by the modules; no third-party Apple types cross this boundary.

#[derive(Clone)]
pub struct Certificate {
    pub der: Vec<u8>,
    pub machine_id: String,
    pub machine_name: String,
}

#[derive(Clone)]
pub struct Team {
    pub id: String,
    pub name: String,
}

pub struct Found {
    pub certificate: Certificate,
    pub team: Team,
}
