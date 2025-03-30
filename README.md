# ARP Spoofing

## Overview

ARP(Address Resolution Protocol) 스푸핑 공격을 구현한 도구
네트워크 상의 특정 호스트의 ARP 테이블을 조작하여 중간자 공격을 수행

## Attack Principle

### ARP Spoofing Process

1. 초기 정보 수집

- 공격자의 MAC/IP 주소 확인
- Sender의 MAC 주소 획득 (ARP Request 사용)
- Target의 MAC 주소 획득

2. ARP 테이블 감염

- Sender에게 위조된 ARP Reply 전송
- Target의 MAC 주소를 공격자의 MAC으로 속임

3. 패킷 가로채기

- Sender -> Target 패킷 캡처
- 캡처된 패킷 수정 및 전달


## Usage
&emsp;``` syntax: ./arp-spoofing <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...] ```

&emsp;``` sample: ./arp-spoofing wlan0 192.168.0.2 192.168.0.1 ```

### Parameters
- interface: 사용할 네트워크 인터페이스
- sender ip: ARP 테이블을 감염시킬 대상 호스트의 IP 주소
- target ip: 감염된 호스트가 속아서 보낼 대상 IP 주소

### Examples

1. 단일 호스트 감염

&emsp;```./arp-spoofing wlan0 192.168.0.2 192.168.0.1```

2. 다중 호스트 감염

&emsp;```./arp-spoofing wlan0 192.168.0.2 192.168.0.1 192.168.0.1 192.168.0.2```


## Technical Details

### Network Protocol Stack

- Layer 2 (Data Link Layer): Ethernet

- Layer 3 (Network Layer): IP, ARP

## Packet Structure

1. Ethernet Frame

&emsp;&emsp;| Destination MAC (6) | Source MAC (6) | Type (2) | Payload |

2. ARP Packet

&emsp;&emsp;| Hardware Type (2) | Protocol Type (2) | HLen (1) | PLen (1) | Operation (2) |

&emsp;&emsp;| Sender MAC (6) | Sender IP (4) | Target MAC (6) | Target IP (4) |

3. IP Packet

&emsp;&emsp;| Version (4) | IHL (4) | ToS (8) | Total Length (16) |

&emsp;&emsp;| Identification (16) | Flags (3) | Fragment Offset (13) |

&emsp;&emsp;| TTL (8) | Protocol (8) | Header Checksum (16) |

&emsp;&emsp;| Source IP Address (32) |

&emsp;&emsp;| Destination IP Address (32) |
