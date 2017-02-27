package com.unhandledexpression.wireguard.protocol;

/**
 * Created by geal on 25/02/2017.
 */

public class Configuration {
    public String myPrivateKey;
    public String myIp;
    public int    myIpPrefix;
    public String route;
    public int    routePrefix   = 24;

    public String myExternalIp;
    public int    myExternalPort;

    public String theirPublicKey = "lbaX78CbaC1My+APL1pcyabXKZcztoQz+TjHkzUGZS0=";
    public String theirHost;
    public int    theirPort;

    public String preSharedKey;

    public Configuration(String myPrivateKey, String myIp, int myIpPrefix, String route,
                         int routePrefix, String myExternalIp, int myExternalPort,
                         String theirPublicKey, String theirHost, int theirPort,
                         String preSharedKey) {
        this.myPrivateKey   = myPrivateKey;
        this.myIp           = myIp;
        this.myIpPrefix     = myIpPrefix;
        this.route          = route;
        this.routePrefix    = routePrefix;
        this.myExternalIp   = myExternalIp;
        this.myExternalPort = myExternalPort;
        this.theirPublicKey = theirPublicKey;
        this.theirHost      = theirHost;
        this.theirPort      = theirPort;
        this.preSharedKey   = preSharedKey;
    }
}
