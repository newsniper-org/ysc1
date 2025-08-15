use cfg_if::cfg_if;

cfg_if! {
    if #[cfg(feature = "ysc1_simd")] {
        pub(crate) mod simd;
    } else {
        pub(crate) mod soft;
    }
}