package com.unhandledexpression.wireguard.protocol;

import android.util.Base64;

/**
 * Created by geal on 25/02/2017.
 */

public class Configuration {
    public byte[] myPrivateKey;
    public String myIp;
    public int    myIpPrefix;
    public String route;
    public int    routePrefix   = 24;

    public String myExternalIp;
    public int    myExternalPort;

    public byte[] theirPublicKey;
    public String theirHost;
    public int    theirPort;

    public String preSharedKey;

    public Configuration(String myPrivateKey, String myIp, int myIpPrefix, String route,
                         int routePrefix, String myExternalIp, int myExternalPort,
                         String theirPublicKey, String theirHost, int theirPort,
                         String preSharedKey) {

        this.myPrivateKey = Base64.decode(myPrivateKey, Base64.DEFAULT);
        this.myIp = myIp;
        this.myIpPrefix = myIpPrefix;
        this.route = route;
        this.routePrefix = routePrefix;
        this.myExternalIp = myExternalIp;
        this.myExternalPort = myExternalPort;
        this.theirPublicKey = Base64.decode(theirPublicKey, Base64.DEFAULT);
        this.theirHost = theirHost;
        this.theirPort = theirPort;
        this.preSharedKey = preSharedKey;
    }

    public Configuration(byte[] myPrivateKey, String myIp, int myIpPrefix, String route,
                         int routePrefix, String myExternalIp, int myExternalPort,
                         byte[] theirPublicKey, String theirHost, int theirPort,
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
