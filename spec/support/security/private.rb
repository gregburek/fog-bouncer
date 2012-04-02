Fog::Bouncer.security :private do
  account "jersey_shore", ENV['AWS_ACCOUNT_ID']

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
  end
end
