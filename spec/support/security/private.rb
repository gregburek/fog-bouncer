Fog::Bouncer.security :private do
  account "jersey_shore", Fog::Bouncer.aws_account_id

  group "douchebag", "Don't let them in!" do
    source "1.1.1.1/1" do
      tcp 7070..8080, 80
    end

    source "0.0.0.0/0" do
      icmp 8..0
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
