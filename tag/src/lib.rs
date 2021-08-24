pub trait ToTag {
    fn to_tag(&self) -> u8;
}

pub trait FromTag: ToTag {
    fn from_tag(tag: u8) -> Self;
}
