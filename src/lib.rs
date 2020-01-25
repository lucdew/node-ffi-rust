use num_bigint::BigUint;
use rand::rngs::OsRng;
use rsa::{PaddingScheme, PublicKey, RSAPrivateKey};
use std::slice;

fn get_private_key() -> RSAPrivateKey {
    // -----BEGIN RSA PRIVATE KEY-----
    // MIIEpAIBAAKCAQEA05e4TZikwmE47RtpWoEG6tkdVTvwYEG2LT/cUKBB4iK49FKW
    // icG4LF5xVU9d1p+i9LYVjPDb61eBGg/DJ+HyjnT+dNO8Fmweq9wbi1e5NMqL5bAL
    // TymXW8yZrK9BW1m7KKZ4K7QaLDwpdrPBjbre9i8AxrsiZkAJUJbAzGDSL+fvmH11
    // xqgbENlr8pICivEQ3HzBu8Q9Iq2rN5oM1dgHjMeA/1zWIJ3qNMkiz3hPdxfkKNdb
    // WuyP8w5fAUFRB2bi4KuNRzyE6HELK5gifD2wlTN600UvGeK5v7zN2BSKv2d2+lUn
    // debnWVbkUimuWpxGlJurHmIvDkj1ZSSoTtNIOwIDAQABAoIBAQDE5wxokWLJTGYI
    // KBkbUrTYOSEV30hqmtvoMeRY1zlYMg3Bt1VFbpNwHpcC12+wuS+Q4B0f4kgVMoH+
    // eaqXY6kvrmnY1+zRRN4p+hNb0U+Vc+NJ5FAx47dpgvWDADgmxVLomjl8Gga9IWNI
    // hjDZLowrtkPXq+9wDaldaFyUFImkb1S1MW9itdLDp/G70TTLNzU6RGg/3J2V02RY
    // 3iL2xEBX/nSgpDbEMI9z9NpC81xHrBanE41IOvyR5B3DoRJzguDA9RGbAiG0/GOd
    // a5w4F3pt6bUm69iMONeYLAf5ig79h31Qiq4nW5RpFcAuLhEG0XXXTsZ3f16A0SwF
    // PZx74eNBAoGBAPgnu/OkGHfHzFmuv0LtSynDLe/LjtloY9WwkKBaiTDdYkohydz5
    // g4Vo/foN9luEYqXyrJE9bFb5dVMr2OePsHvUBcqZpIS89Z8Bm73cs5M/K85wYwC0
    // 97EQEgxd+QGBWQZ8NdowYaVshjWlK1QnOzEnG0MR8Hld9gIeY1XhpC5hAoGBANpI
    // F84Aid028q3mo/9BDHPsNL8bT2vaOEMb/t4RzvH39u+nDl+AY6Ox9uFylv+xX+76
    // CRKgMluNH9ZaVZ5xe1uWHsNFBy4OxSA9A0QdKa9NZAVKBFB0EM8dp457YRnZCexm
    // 5q1iW/mVsnmks8W+fYlc18W5xMSX/ecwkW/NtOQbAoGAHabpz4AhKFbodSLrWbzv
    // CUt4NroVFKdjnoodjfujfwJFF2SYMV5jN9LG3lVCxca43ulzc1tqka33Nfv8TBcg
    // WHuKQZ5ASVgm5VwU1wgDMSoQOve07MWy/yZTccTc1zA0ihDXgn3bfR/NnaVh2wlh
    // CkuI92eyW1494hztc7qlmqECgYEA1zenyOQ9ChDIW/ABGIahaZamNxsNRrDFMl3j
    // AD+cxHSRU59qC32CQH8ShRy/huHzTaPX2DZ9EEln76fnrS4Ey7uLH0rrFl1XvT6K
    // /timJgLvMEvXTx/xBtUdRN2fUqXtI9odbSyCtOYFL+zVl44HJq2UzY4pVRDrNcxs
    // SUkQJqsCgYBSaNfPBzR5rrstLtTdZrjImRW1LRQeDEky9WsMDtCTYUGJTsTSfVO8
    // hkU82MpbRVBFIYx+GWIJwcZRcC7OCQoV48vMJllxMAAjqG/p00rVJ+nvA7et/nNu
    // BoB0er/UmDm4Ly/97EO9A0PKMOE5YbMq9s3t3RlWcsdrU7dvw+p2+A==
    // -----END RSA PRIVATE KEY-----

    RSAPrivateKey::from_components(
            BigUint::parse_bytes(b"00d397b84d98a4c26138ed1b695a8106ead91d553bf06041b62d3fdc50a041e222b8f4529689c1b82c5e71554f5dd69fa2f4b6158cf0dbeb57811a0fc327e1f28e74fe74d3bc166c1eabdc1b8b57b934ca8be5b00b4f29975bcc99acaf415b59bb28a6782bb41a2c3c2976b3c18dbadef62f00c6bb226640095096c0cc60d22fe7ef987d75c6a81b10d96bf292028af110dc7cc1bbc43d22adab379a0cd5d8078cc780ff5cd6209dea34c922cf784f7717e428d75b5aec8ff30e5f0141510766e2e0ab8d473c84e8710b2b98227c3db095337ad3452f19e2b9bfbccdd8148abf6776fa552775e6e75956e45229ae5a9c46949bab1e622f0e48f56524a84ed3483b", 16).unwrap(),
            BigUint::parse_bytes(b"65537", 10).unwrap(),
            BigUint::parse_bytes(b"00c4e70c689162c94c660828191b52b4d8392115df486a9adbe831e458d73958320dc1b755456e93701e9702d76fb0b92f90e01d1fe248153281fe79aa9763a92fae69d8d7ecd144de29fa135bd14f9573e349e45031e3b76982f583003826c552e89a397c1a06bd2163488630d92e8c2bb643d7abef700da95d685c941489a46f54b5316f62b5d2c3a7f1bbd134cb37353a44683fdc9d95d36458de22f6c44057fe74a0a436c4308f73f4da42f35c47ac16a7138d483afc91e41dc3a1127382e0c0f5119b0221b4fc639d6b9c38177a6de9b526ebd88c38d7982c07f98a0efd877d508aae275b946915c02e2e1106d175d74ec6777f5e80d12c053d9c7be1e341", 16).unwrap(),
            vec![
                BigUint::parse_bytes(b"00f827bbf3a41877c7cc59aebf42ed4b29c32defcb8ed96863d5b090a05a8930dd624a21c9dcf9838568fdfa0df65b8462a5f2ac913d6c56f975532bd8e78fb07bd405ca99a484bcf59f019bbddcb3933f2bce706300b4f7b110120c5df9018159067c35da3061a56c8635a52b54273b31271b4311f0795df6021e6355e1a42e61",16).unwrap(),
                BigUint::parse_bytes(b"00da4817ce0089dd36f2ade6a3ff410c73ec34bf1b4f6bda38431bfede11cef1f7f6efa70e5f8063a3b1f6e17296ffb15feefa0912a0325b8d1fd65a559e717b5b961ec345072e0ec5203d03441d29af4d64054a04507410cf1da78e7b6119d909ec66e6ad625bf995b279a4b3c5be7d895cd7c5b9c4c497fde730916fcdb4e41b", 16).unwrap()
            ],
        )
}

#[repr(C)]
pub struct ArrayStruct {
    data: *const u8,
    len: usize,
}

#[no_mangle]
pub fn encrypt(data: *const u8, len: usize) -> *const ArrayStruct {
    /* Lets turn it into format thats easier to operate on */
    let array = unsafe { slice::from_raw_parts(data, len as usize) };

    let mut rng = OsRng;
    //let bits = 2048;
    /*    let key = RSAPrivateKey::new(&mut rng, bits).expect("failed to generate a key");*/

    let key = get_private_key();

    // Encrypt
    let enc_data = key
        .encrypt(&mut rng, PaddingScheme::PKCS1v15, &array)
        .expect("failed to encrypt");

    let buf = enc_data.as_ptr();
    let len = enc_data.len();

    /* Stop Rust from destroying the variable */
    std::mem::forget(enc_data);

    unsafe {
        std::mem::transmute(Box::new(ArrayStruct {
            data: buf,
            len: len,
        }))
    }

    /*let mut return_array = vec![];

    /* The return values are function of input values */
    for v in array.iter() {
        return_array.push(v + 1);
    }*/

    /* Obtain a pointer to the array */
    //let buf = enc_data.as_ptr();

    /* Stop Rust from destroying the variable */
    //std::mem::forget(enc_data);

    //buf
}
