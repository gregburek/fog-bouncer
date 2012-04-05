Fog::Bouncer.security :private do
  account "jersey_shore", Fog::Bouncer.aws_account_id

  define :ping, "0.0.0.0/0" do
    icmp :ping
  end

  define :ssh, "0.0.0.0/0" do
    tcp 22
  end

  use :ssh

  group "douchebag", "Don't let them in!" do
    use :ping

    source "1.1.1.1/1" do
      tcp 7070..8080, 80
    end

    source "0.0.0.0/0" do
      icmp :ping
    end
  end

  group "guido", "Definitely don't let them in!" do
    source "douchebag@jersey_shore" do
      tcp 7070..8080
      udp 8081
    end

    source "other@#{Fog::Bouncer.aws_account_id}" do
      icmp :all
    end
  end

  group "other", "Some other randomness" do
    source "douchebag" do
      tcp 80
    end

    source "douchebag" do
      udp 8080
    end
  end
end
