# fog-bouncer

![fog-bouncer](https://github.com/dylanegan/fog-bouncer/raw/master/bouncer.jpg)

A simple way to define and manage security groups for AWS through fog.

## Usage

```
Fog::Bouncer.security do
  account "user", "1234567890"

  group "base", "Base Security Group" do
    source "0.0.0.0/0" do
      icmp 8..0
    end

    source "10.0.0.0/8" do
      tcp 80, 22, 8080..8081
    end
  end

  group "other", "Other Security Group" do
    source "default@user" do
      tcp 22
    end
  end
end
```
