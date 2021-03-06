/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package gpake;

import java.io.File;
import java.io.FileNotFoundException;
import java.io.PrintStream;
import java.math.BigInteger;
import java.security.Security;
import java.util.LinkedList;
import java.util.List;
import java.util.concurrent.TimeUnit;

/**
 *
 * @author Taras Mychaskiw
 */
public class GPAKE {

    static PrintStream print = null;

    final static BigInteger spekeP = new BigInteger("AC6BDB41324A9A9BF166DE5E1389582FAF72B6651987EE07FC3192943DB56050A37329CBB4A099ED8193E0757767A13DD52312AB4B03310DCD7F48A9DA04FD50E8083969EDB767B0CF6095179A163AB3661A05FBD5FAAAE82918A9962F0B93B855F97993EC975EEAA80D740ADBF4FF747359D041D5C33EA71D281E446B14773BCA97B43A23FB801676BD207A436C6481F1D2B9078717461A5B9D32E688F87748544523B524B0D57D5EA77A2775D2ECFA032CFBDBF52FB3786160279004E57AE6AF874E7303CE53299CCC041C7BC308D82A5698F3A8D0C38271AE35F8E9DBFBB694B5C803D89F7AE435DE236D525F54759B65E372FCD68EF20FA7111F9E4AFF73", 16);
    final static BigInteger spekeG = new BigInteger("3");

    final static BigInteger jpakeP = new BigInteger("C196BA05AC29E1F9C3C72D56DFFC6154A033F1477AC88EC37F09BE6C5BB95F51C296DD20D1A28A067CCC4D4316A4BD1DCA55ED1066D438C35AEBAABF57E7DAE428782A95ECA1C143DB701FD48533A3C18F0FE23557EA7AE619ECACC7E0B51652A8776D02A425567DED36EABD90CA33A1E8D988F0BBB92D02D1D20290113BB562CE1FC856EEB7CDD92D33EEA6F410859B179E7E789A8F75F645FAE2E136D252BFFAFF89528945C1ABE705A38DBC2D364AADE99BE0D0AAD82E5320121496DC65B3930E38047294FF877831A16D5228418DE8AB275D7D75651CEFED65F78AFC3EA7FE4D79B35F62A0402A1117599ADAC7B269A59F353CF450E6982D3B1702D9CA83", 16);
    final static BigInteger jpakeQ = new BigInteger("90EAF4D1AF0708B1B612FF35E0A2997EB9E9D263C9CE659528945C0D", 16);
    final static BigInteger jpakeG = new BigInteger("A59A749A11242C58C894E9E5A91804E8FA0AC64B56288F8D47D51B1EDC4D65444FECA0111D78F35FC9FDD4CB1F1B79A3BA9CBEE83A3F811012503C8117F98E5048B089E387AF6949BF8784EBD9EF45876F2E6A5A495BE64B6E770409494B7FEE1DBB1E4B2BC2A53D4F893D418B7159592E4FFFDF6969E91D770DAEBD0B5CB14C00AD68EC7DC1E5745EA55C706C4A1C5C88964E34D09DEB753AD418C1AD0F4FDFD049A955E5D78491C0B7A2F1575A008CCD727AB376DB6E695515B05BD412F5B8C2F4C77EE10DA48ABD53F5DD498927EE7B692BBBCDA2FB23A516C5B4533D73980B2A3B60E384ED200AE21B40D273651AD6060C13D97FD69AA13C5611A51B9085", 16);

    //1024-bit
    //final static BigInteger dragonflyP = new BigInteger("E0A67598CD1B763BC98C8ABB333E5DDA0CD3AA0E5E1FB5BA8A7B4EABC10BA338FAE06DD4B90FDA70D7CF0CB0C638BE3341BEC0AF8A7330A3307DED2299A0EE606DF035177A239C34A912C202AA5F83B9C4A7CF0235B5316BFC6EFB9A248411258B30B839AF172440F32563056CB67A861158DDD90E6A894C72A5BBEF9E286C6B", 16);
    //final static BigInteger dragonflyQ = new BigInteger("E950511EAB424B9A19A2AEB4E159B7844C589C4F", 16);
    //final static BigInteger dragonflyG = new BigInteger("D29D5121B0423C2769AB21843E5A3240FF19CACC792264E3BB6BE4F78EDD1B15C4DFF7F1D905431F0AB16790E1F773B5CE01C804E509066A9919F5195F4ABC58189FD9FF987389CB5BEDF21B4DAB4F8B76A055FFE2770988FE2EC2DE11AD92219F0B351869AC24DA3D7BA87011A701CE8EE7BFE49486ED4527B7186CA4610A75", 16);

    //2048-bit - should be used for fair comparison of times
    final static BigInteger dragonflyP = new BigInteger("F56C2A7D366E3EBDEAA1891FD2A0D099436438A673FED4D75F594959CFFEBCA7BE0FC72E4FE67D91D801CBA0693AC4ED9E411B41D19E2FD1699C4390AD27D94C69C0B143F1DC88932CFE2310C886412047BD9B1C7A67F8A25909132627F51A0C866877E672E555342BDF9355347DBD43B47156B2C20BAD9D2B071BC2FDCF9757F75C168C5D9FC43131BE162A0756D1BDEC2CA0EB0E3B018A8B38D3EF2487782AEB9FBF99D8B30499C55E4F61E5C7DCEE2A2BB55BD7F75FCDF00E48F2E8356BDB59D86114028F67B8E07B127744778AFF1CF1399A4D679D92FDE7D941C5C85C5D7BFF91BA69F9489D531D1EBFA727CFDA651390F8021719FA9F7216CEB177BD75", 16);
    final static BigInteger dragonflyQ = new BigInteger("C24ED361870B61E0D367F008F99F8A1F75525889C89DB1B673C45AF5867CB467", 16);
    final static BigInteger dragonflyG = new BigInteger("8DC6CC814CAE4A1C05A3E186A6FE27EABA8CDB133FDCE14A963A92E809790CBA096EAA26140550C129FA2B98C16E84236AA33BF919CD6F587E048C52666576DB6E925C6CBE9B9EC5C16020F9A44C9F1C8F7A8E611C1F6EC2513EA6AA0B8D0F72FED73CA37DF240DB57BBB27431D618697B9E771B0B301D5DF05955425061A30DC6D33BB6D2A32BD0A75A0A71D2184F506372ABF84A56AEEEA8EB693BF29A640345FA1298A16E85421B2208D00068A5A42915F82CF0B858C8FA39D43D704B6927E0B2F916304E86FB6A1B487F07D8139E428BB096C6D67A76EC0B8D4EF274B8A2CF556D279AD267CCEF5AF477AFED029F485B5597739F5D0240F67C2D948A6279", 16);

    final static BigInteger ppkP = jpakeP;
    final static BigInteger ppkQ = jpakeQ;
    final static BigInteger ppkG = jpakeG;
    final static BigInteger h1Const = new BigInteger("B134E07C599985AC1074716A63E1ED76E89D60D757BA36AF9FC194C46C433F27A5D9A935BEB969052D6E3362ADD00126CC06C4106FE6F12537F5421251D03061C5625300C4A7A03254C58A58A5A3EE3C88513CD78CA969DD98EAE4C1C21A65C4614CB474C6BACA6E89FD2B37FDB1B6E52F8168582F6CBD0A7A6A55BE619DE2658F40080FD62FD0F13DBDF548A033012740AE5C4FCD46A4ED89C49BC085476C5E5F92A2B1E5E0DA0FB084A32B5E360929136E55BCAC73896F5F19B4EB1C3661E84F1D6D1AE2D010F16040E6D90DC2EEB13EEF5333C59F5275725CB9F5BD00B2A66AC21C06E8C661912C5DB8A05EFDC15B1AE7172314F17E94E07F9427008F857B", 16);
    final static BigInteger h3Const = new BigInteger("8C081A8F7C64708F99DFD252FC3E78D7220DD1072E739A8C49422C6A8167EF35CC13D77BE476A469B56E346916B40E9268A9CFE40ECA902C719642A78513A79FFB4D14CEB1F9552A5E6E77F66601791BE47BC48097A1AADC803BFACD05D5A2C2ABD593A20D93B12F87D3B357B5282B27022D66D171E3412A6D90595A906AEAB48ADED6C579CDCEC13BEBFB173C1D534A58866A6D0BB825176FD40E5CD88E99223C8B3039E81EFE550EBE9044F83E2BE84B76289771B04856320215991F23CA2DA2D499417258968BB538CE56EBD0EB0EE66DAFDB06BEA55831E2C25A3FB4619EF734C95A6CA838960B012DA586741D092DD808962C0BE001EE03155FC9CB1D6B", 16);
    /**
     * sets the group for each member of the gpake
     *
     * @param pake the group to initialize
     */
    private void initGroup(PAKE[] pake) {
        for (int i = 0; i < pake.length; i++) {
            pake[i].setGroup(pake, i);
        }
    }

    /**
     * runs one gpake protocol
     *
     * @param pake the group to run on
     * @param roundTimer timers for each of the rounds
     * @param verTimer timers for each verification round
     * @param verZTimer timer for verifying z
     * @param keyTimer timer for calculating group keys
     */
    private BigInteger[] run(PAKE[] pake, Timer[] roundTimer, Timer[] verTimer, Timer verZTimer, Timer keyTimer) {
        BigInteger[] keys = new BigInteger[pake.length];
        for (int round = 1; round <= pake[0].getNumRounds(); round++) {
            roundTimer[round].start();
            for (PAKE pakeInstance : pake) {
                pakeInstance.doRound(round);
            }
            roundTimer[round].stop();
            System.out.println(roundTimer[round] + ", time: " + roundTimer[round].getTime() + Timer.getUnit(roundTimer[round].getDefaultTimeUnit()));

            if (round == 1) {    //in the first round, need to verify the Z value
                verZTimer.start();
                for (int i = 0; i < pake.length; i++) {
                    pake[i].verifyZ(pake[i == 0 ? pake.length - 1 : i - 1], pake[(i + 1) % pake.length]);
                }
                verZTimer.stop();
                System.out.println(verZTimer + ", time: " + verZTimer.getTime() + Timer.getUnit(verZTimer.getDefaultTimeUnit()));
            }
            verTimer[round].start();
            for (PAKE pakeInstance : pake) {
                pakeInstance.verifyRound(round);
            }
            verTimer[round].stop();
            System.out.println(verTimer[round] + ", time: " + verTimer[round].getTime() + Timer.getUnit(verTimer[round].getDefaultTimeUnit()));
        }
        keyTimer.start();
        for (int i = 0; i < pake.length; i++) {
            keys[i] = pake[i].getKey();
        }
        keyTimer.stop();
        System.out.println(keyTimer + ", time: " + keyTimer.getTime() + Timer.getUnit(keyTimer.getDefaultTimeUnit()));
        return keys;
    }

    /**
     * displays the group keys after the protocol is complete
     *
     * @param keys the group keys
     */
    private void displayKeys(BigInteger[] keys) {
        for (int i = 0; i < keys.length; i++) {
            System.out.println("key #" + i + ": " + keys[i]);
        }
    }

    /**
     * displays the results after a run.
     *
     * @param size the group size
     * @param failures the fail messages
     * @param roundTimer timers for each of the rounds
     * @param verTimer timers for each verification round
     * @param verZTimer timer for verifying z
     * @param keyTimer timer for calculating group keys
     */
    private void displayResults(int size, List<String> failures, Timer[] roundTimer, Timer[] verTimer, Timer verZTimer, Timer keyTimer, PrintStream out) {
        out.println("overall results for n=" + size);
        out.println("total number of failures: " + failures.size());
        if (!failures.isEmpty()) {
            out.println(failures);
        }
        for (int round = 1; round < roundTimer.length; round++) {
            out.println(roundTimer[round]);
            out.println(verTimer[round]);
        }
        out.println(verZTimer);
        out.println(keyTimer);
        out.println();
    }

    /**
     * runs and times the gpake protocol
     *
     * @param pake the group
     * @param iterations the number of iterations
     */
    public void runTest(PAKE[] pake, int iterations) {
        initGroup(pake);    //tell everyone about the group and their position in it

        int numRounds = pake[0].getNumRounds();
        Timer[] roundTimer = new Timer[numRounds + 1];
        Timer[] verTimer = new Timer[numRounds + 1];
        Timer verZTimer = new Timer("verify Z", TimeUnit.NANOSECONDS);
        Timer keyTimer = new Timer("key calc", TimeUnit.NANOSECONDS);
        for (int round = 1; round <= numRounds; round++) {
            roundTimer[round] = new Timer("round  " + round, TimeUnit.NANOSECONDS);
            verTimer[round] = new Timer("verify " + round, TimeUnit.NANOSECONDS);
        }

        List<String> failures = new LinkedList<>();
        for (int it = 0; it < iterations; it++) {
            try {
                System.out.println("numUsers = " + pake.length + "\titeration " + (it + 1));
                BigInteger[] keys = run(pake, roundTimer, verTimer, verZTimer, keyTimer);
                displayKeys(keys);
                System.out.println();
            } catch (SecurityException e) {
                failures.add(e.getMessage());
                System.out.println("protocol failure: " + e);
                for (int round = 1; round <= numRounds; round++) {
                    roundTimer[round].abort(it);
                    verTimer[round].abort(it);
                }
                verZTimer.abort(it);
                keyTimer.abort(it);
                it--;   //decrease to run the correct number of trials still
            }
        }
        displayResults(pake.length, failures, roundTimer, verTimer, verZTimer, keyTimer, System.out);
        if (print != null) {
            displayResults(pake.length, failures, roundTimer, verTimer, verZTimer, keyTimer, print);
        }
    }

    public static final int minUsers = 3;
    public static final int maxUsers = 20;
    public static final int maxIterations = 100;

    public static void main(String[] args) {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
        //speke();
        //jpake();
        //dragonfly();
        ppk();
    }

    /**
     * runs speke tests
     */
    public static void speke() {
        try {
            print = new PrintStream(new File("speke.txt"));
        } catch (FileNotFoundException ex) {
        }
        for (int n = minUsers; n <= maxUsers; n++) {
            SPEKE[] group = new SPEKE[n];
            for (int i = 0; i < group.length; i++) {
                group[i] = new SPEKE(spekeP, spekeG, "password");
            }
            new GPAKE().runTest(group, maxIterations);
        }
    }

    /**
     * runs jpake tests
     */
    public static void jpake() {
        try {
            print = new PrintStream(new File("jpake.txt"));
        } catch (FileNotFoundException ex) {
        }
        for (int n = minUsers; n <= maxUsers; n++) {
            JPAKE[] group = new JPAKE[n];
            for (int i = 0; i < group.length; i++) {
                group[i] = new JPAKE(jpakeP, jpakeQ, jpakeG, "password");
            }
            new GPAKE().runTest(group, maxIterations);
        }
    }

    /**
     * runs dragonfly tests
     */
    public static void dragonfly() {
        try {
            print = new PrintStream(new File("dragonfly.txt"));
        } catch (FileNotFoundException ex) {
        }
        for (int n = minUsers; n <= maxUsers; n++) {
            Dragonfly[] group = new Dragonfly[n];
            for (int i = 0; i < group.length; i++) {
                group[i] = new Dragonfly(dragonflyP, dragonflyQ, dragonflyG, "password");
            }
            new GPAKE().runTest(group, maxIterations);
        }
    }

    /**
     * runs PPK tests
     */
    public static void ppk() {
        try {
            print = new PrintStream(new File("ppk.txt"));
        } catch (FileNotFoundException ex) {
        }
        for (int n = minUsers; n <= maxUsers; n++) {
            PPK[] group = new PPK[n];
            for (int i = 0; i < group.length; i++) {
                group[i] = new PPK(ppkP, ppkQ, ppkG, h1Const, h3Const, "password");
            }
            new GPAKE().runTest(group, maxIterations);
        }

    }

}
