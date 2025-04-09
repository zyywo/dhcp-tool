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

/**计算数据的校验和

1. 把数据分割成16位的word（字）
2. 把所有word相加得到计算和
3. 如果计算和溢出就处理溢出：把溢出位放到末尾相加，比如计算和是`203b4`，则：`03b4+2=03b6`
4. 取计算和的反码就是校验和,


**UDP校验和计算**：伪首部（12字节） + UDP首部（8字节） + UDP载荷

伪首部：4字节源IP，4字节目的IP，2字节协议类型（UDP恒为0x0011），2字节UDP报文长度

UDP首部：2字节源端口，2字节目的端口，2字节UDP报文长度，2字节校验和（计算前校验和置0）

**IP头部校验和计算**：只计算整个头部（计算前校验和字段应为0）。
*/
pub fn checksum(packet: &[u8]) -> u16 {
    let mut sum: u32 = 0;
    packet.chunks(2).for_each(|b| {
        let word = if b.len() < 2 {
            b[0] as u16
        } else {
            (b[0] as u16) << 8 | b[1] as u16
        };
        sum += word as u32;
    });
    while (sum >> 16) > 0 {
        sum = (sum >> 16) + (sum & 0xffff);
    }
    !(sum as u16)
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
    fn test_checksum() {
        let mut check_sum;
        let mut wannted;

        check_sum = checksum(&[
            0x10, 0x10, 0x20, 0x20, 0x00, 0x14, 0x00, 0x00, 0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc,
        ]);
        wannted = 0xcc52;
        assert_eq!(
            check_sum, wannted,
            "计算结果0x{:04x}， 期望结果：0x{:04x}",
            check_sum, wannted
        );

        check_sum = checksum(&[
            0x0a, 0xaa, 0x3b, 0xbf, 0xd2, 0x0e, 0x96, 0x0d, 0x00, 0x11, 0x00, 0x1c, 0xd1, 0x23,
            0x27, 0x42, 0x00, 0x1c, 0x00, 0x00, 0x6c, 0x41, 0x56, 0x61, 0x00, 0x00, 0x0e, 0x00,
            0xf8, 0xb6, 0xd4, 0x01, 0x93, 0x13, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]);
        wannted = 0x285c;
        assert_eq!(
            check_sum, wannted,
            "计算结果0x{:04x}， 期望结果：0x{:04x}",
            check_sum, wannted
        );

        check_sum = checksum(&[0x84, 0xeb, 0xdf, 0xea, 0x9e, 0xdf]);
        wannted = 0xfc49;
        assert_eq!(
            check_sum, wannted,
            "计算结果0x{:04x}， 期望结果：0x{:04x}",
            check_sum, wannted
        );
    }
}
