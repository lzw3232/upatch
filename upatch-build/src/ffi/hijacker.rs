extern "C" {
    pub fn upatch_hijacker_init() -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn upatch_hijacker_register(
        prey_name: *const ::std::os::raw::c_char,
        hijacker_name: *const ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;
}
extern "C" {
    pub fn upatch_hijacker_unregister(
        prey_name: *const ::std::os::raw::c_char,
        hijacker_name: *const ::std::os::raw::c_char,
    ) -> ::std::os::raw::c_int;
}
