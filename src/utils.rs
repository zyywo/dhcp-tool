/** u8列表转换为mac地址

比如 `[255, 255, 255, 255, 255, 255] => "ff:ff:ff:ff:ff:ff"`
 */
pub fn u8_to_mac(u: &[u8]) -> String {
    let mut mac = String::new();
    for i in u {
        mac.push_str(format!("{:02x}", i).as_str());
        mac.push(':');
    }
    mac.pop();
    mac
}

/**把mac地址转换为u8列表

比如 `01:02:03:dd:ee:ff => [1, 2, 3, 221, 238, 255]`
 */
pub fn mac_to_u8(s: &str) -> Vec<u8> {
    let s1 = s.replace(":", "");
    let val: Vec<u8> = bytes_str_to_u8(s1.as_str()).try_into().unwrap();
    val
}

/**把u16转换为u8列表，比如：

`[0x285c] => [40, 92]`,

`[10332] => [40, 92]`,

`[0xffff] => [255, 255]`，

`[0x0001, 0x285c] => [0, 1, 40, 92]`
*/
pub fn u16_to_u8(u: &[u16]) -> Vec<u8> {
    let mut u8_list = Vec::new();
    for i in u {
        let h = i >> 8 & 0x00ff;
        let l = i & 0x00ff;
        u8_list.push(h as u8);
        u8_list.push(l as u8);
    }
    u8_list
}

/**把i32转换为u8列表，比如：

`[0xffffff] => [0, 255, 255, 255]`,

`[16777215] => [0, 255, 255, 255]`
*/
pub fn u32_to_u8(i: &[u32]) -> Vec<u8> {
    let mut u8_list = Vec::new();
    for j in i {
        let d0 = j & 0x00ff;
        let d1 = j >> 8 & 0x00ff;
        let d2 = j >> 16 & 0x00ff;
        let d3 = j >> 24 & 0x00ff;
        u8_list.push(d3 as u8);
        u8_list.push(d2 as u8);
        u8_list.push(d1 as u8);
        u8_list.push(d0 as u8);
    }
    u8_list
}

/** 把字节字符串转为u8列表

比如 `"ff00ff10" => [255, 0, 255, 16]`
 */
fn bytes_str_to_u8(s: &str) -> Vec<u8> {
    let mut return_val = Vec::new();

    let mut siter = s.chars().enumerate();
    while let Some((i, v)) = siter.next() {
        if i % 2 != 0 {
            continue;
        };
        let h = match v.to_digit(16) {
            Some(x) => x,
            None => 255,
        };
        let l = match siter.next().unwrap().1.to_digit(16) {
            Some(x) => x,
            None => 255,
        };
        let a: u8 = (h * 16 + l).try_into().unwrap();
        return_val.push(a);
    }
    return_val
}

/**计算UDP报文与IP报文的头部校验和，如果报文不是偶数个，会自动补一个全零字节。

UDP校验和计算：4字节源IP，4字节目的IP，2字节协议类型（UDP恒为0x0011），2字节UDP长度，最后是UDP载荷（计算前UDP报文的校验和字段应为0）。

IP校验和计算：只计算整个头部（计算前IP报文的校验和字段应为0）。
*/
pub fn udp_ip_checksum(packet: &[u8]) -> u16 {
    let mut sum: u16 = 0;
    for j in packet.chunks(2) {
        // 这里相当于补0后相加
        let (a, overflow) = if j.len() < 2 {
            sum.overflowing_add(j[0] as u16 * 256)
        } else {
            let word: u16 = j[0] as u16 * 256 + j[1] as u16;
            sum.overflowing_add(word)
        };
        sum = a;
        if overflow {
            sum += 1;
        }
    }
    !sum
}

#[cfg(test)]
mod utils_tests {
    use super::*;

    #[test]
    fn test_str_to_u8() {
        assert_eq!(bytes_str_to_u8("ff00ff10"), [255, 0, 255, 16]);
    }

    #[test]
    fn test_mac_to_u8() {
        assert_eq!(mac_to_u8("01:02:03:dd:ee:ff"), [1, 2, 3, 221, 238, 255]);
    }

    #[test]
    fn test_u16_to_u8() {
        assert_eq!(u16_to_u8(&[0xffff]), [255, 255]);
        assert_eq!(u16_to_u8(&[0x0000]), [0, 0]);
        assert_eq!(u16_to_u8(&[65535]), [255, 255]);
        assert_eq!(u16_to_u8(&[0x285c]), [40, 92]);
        assert_eq!(u16_to_u8(&[0x0001, 0x285c]), [0, 1, 40, 92]);
    }

    #[test]
    fn test_i32_to_u8() {
        assert_eq!(u32_to_u8(&[16777215]), [0, 255, 255, 255]);
        assert_eq!(u32_to_u8(&[0xffffff]), [0, 255, 255, 255]);
    }

    #[test]
    fn test_u8_to_mac() {
        assert_eq!(u8_to_mac(&[1, 2, 3]), "01:02:03");
        assert_eq!(u8_to_mac(&[1, 2, 3, 221, 238, 255]), "01:02:03:dd:ee:ff");
        assert_eq!(
            u8_to_mac(&[255, 255, 255, 255, 255, 255]),
            "ff:ff:ff:ff:ff:ff"
        );
    }

    #[test]
    fn test_udp_checksum() {
        assert_eq!(
            udp_ip_checksum(&[
                0x10, 0x10, 0x20, 0x20, 0x00, 0x14, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
            ]),
            0xcc52
        );
        assert_eq!(
            udp_ip_checksum(&[
                0x0a, 0xaa, 0x3b, 0xbf, 0xd2, 0x0e, 0x96, 0x0d, 0x00, 0x11, 0x00, 0x1c, 0xd1, 0x23,
                0x27, 0x42, 0x00, 0x1c, 0x00, 0x00, 0x6c, 0x41, 0x56, 0x61, 0x00, 0x00, 0x0e, 0x00,
                0xf8, 0xb6, 0xd4, 0x01, 0x93, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
            ]),
            0x285c
        );
    }
}
