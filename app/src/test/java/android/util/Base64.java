package android.util;

/** JVM stand-in for android.util.Base64 so YubiKit runs in local unit tests. */
public class Base64 {
    public static final int DEFAULT = 0, NO_PADDING = 1, NO_WRAP = 2, CRLF = 4, URL_SAFE = 8, NO_CLOSE = 16;

    public static byte[] decode(String s, int flags) {
        String t = s.trim().replace('-', '+').replace('_', '/').replaceAll("\\s", "");
        return java.util.Base64.getDecoder().decode(t);
    }

    public static byte[] decode(byte[] b, int flags) { return decode(new String(b), flags); }

    public static String encodeToString(byte[] b, int flags) {
        java.util.Base64.Encoder e = (flags & URL_SAFE) != 0 ? java.util.Base64.getUrlEncoder() : java.util.Base64.getEncoder();
        if ((flags & NO_PADDING) != 0) e = e.withoutPadding();
        return e.encodeToString(b);
    }

    public static byte[] encode(byte[] b, int flags) { return encodeToString(b, flags).getBytes(); }
}
