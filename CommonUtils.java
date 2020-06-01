package com.rh.cwcd;

import com.alibaba.fastjson.JSON;
import com.rh.cwcd.dto.notice.EduNotice;
import org.jdom.Document;
import org.jdom.Element;
import org.jdom.input.SAXBuilder;
import org.xml.sax.InputSource;

import javax.servlet.http.HttpServletRequest;
import java.io.PrintWriter;
import java.io.StringReader;
import java.io.StringWriter;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.MessageDigest;
import java.text.SimpleDateFormat;
import java.util.*;

/**
 * @author liaocheng
 * @date: 2020-02-17 11:39
 */
public class CommonUtils {

    /**
     * 时间格式化 年-月-日 时:分:秒
     */
    private static final String YMDHMS = "yyyy-MM-dd HH:mm:ss";

    /**
     * 一亿
     */
    private static final long MAX = 100000000;

    private static int id = 10000;

    /**
     * 年月日
     */
    private static final String YMD = "yyMMdd";

    /**
     * 当前时间戳
     */
    private static final Long NOWTIME = System.currentTimeMillis();

    /**
     * 获取格式化过后的当前时间
     *
     * @return 2020-02-17 11:44:31
     */
    public static String getNowFormatTime() {
        SimpleDateFormat simpleDateFormat = new SimpleDateFormat(YMDHMS);
        return simpleDateFormat.format(System.currentTimeMillis());
    }

    /**
     * 获取当前时间戳
     *
     * @return 1581911390
     */
    public static Long getTimeStamp() {
        return NOWTIME / 1000;
    }

    /**
     * 获取id
     *
     * @return
     */
//    public static Long getId() {
//        String ipAddress = "";
//
//        try {
//            //获取服务器IP地址
//            ipAddress = InetAddress.getLocalHost().getHostAddress();
//        } catch (Exception e) {
//            e.printStackTrace();
//        }
//
//        String uuid = ipAddress + "$" + UUID.randomUUID().toString().replaceAll("-", "").toUpperCase();
//
//        long suffix = Math.abs(uuid.hashCode() % MAX);
//
//        SimpleDateFormat sdf = new SimpleDateFormat(YMD);
//
//        String time = sdf.format(new Date(System.currentTimeMillis()));
//
//        long prefix = Long.parseLong(time) * MAX;
//
//        return Long.parseLong(String.valueOf(prefix + suffix));
//    }

    /**
     * md5 工具
     *
     * @param str
     * @return
     */
    public static String md5(String str) {
        try {
            MessageDigest md = MessageDigest.getInstance("MD5");
            md.update(str.getBytes());
            byte[] b = md.digest();
            StringBuilder buf = new StringBuilder("");

            for (int b1 : b) {
                int i = b1;
                if (i < 0) {
                    i += 256;
                }
                if (i < 16) {
                    buf.append("0");
                }
                buf.append(Integer.toHexString(i));
            }
            str = buf.toString();
        } catch (Exception var6) {
            var6.printStackTrace();
        }

        return str;
    }

    public static int generatorSixSmsCode() {
        for (; ; ) {
            int i1 = new Random().nextInt(999999);
            if (i1 > 100000) {
                return i1;
            }
        }
    }

    /**
     * 获取格式化时间，由于微信支付设置过期时间
     *
     * @return
     */
    public static String getStringDate(int minute) {
        Date now = new Date();
        Date afterDate = new Date(now.getTime() + minute * 60 * 1000);
        SimpleDateFormat formatter = new SimpleDateFormat("yyyyMMddHHmmss");
        return formatter.format(afterDate);
    }

    /**
     * 获取用户真实IP地址，不使用request.getRemoteAddr();的原因是有可能用户使用了代理软件方式避免真实IP地址。
     * 可是，如果通过了多级反向代理的话，X-Forwarded-For的值并不止一个，而是一串IP值，究竟哪个才是真正的用户端的真实IP呢？
     * 答案是取X-Forwarded-For中第一个非unknown的有效IP字符串
     *
     * @param request
     * @return
     */
    public static String getIpAddress(HttpServletRequest request) {
        String ip = request.getHeader("x-forwarded-for");
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("Proxy-Client-IP");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("WL-Proxy-Client-IP");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_CLIENT_IP");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getHeader("HTTP_X_FORWARDED_FOR");
        }
        if (ip == null || ip.length() == 0 || "unknown".equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
            if ("127.0.0.1".equals(ip) || "0:0:0:0:0:0:0:1".equals(ip)) {
                //根据网卡取本机配置的IP
                InetAddress inet = null;
                try {
                    inet = InetAddress.getLocalHost();
                } catch (UnknownHostException e) {
                    e.printStackTrace();
                }
                ip = inet.getHostAddress();
            }
        }
        return ip;
    }

    /**
     * 二次签名H5
     *
     * @param prepay_id
     * @param appid
     * @param nonce_str
     * @return
     */
    public static String createSecondSignH5(String prepay_id, String appid, String nonce_str, String timestape) {
        String secondSign = "";
        SortedMap<Object, Object> parameters = new TreeMap<Object, Object>();
        parameters.put("appId", appid);
        parameters.put("nonceStr", nonce_str);
        parameters.put("package", "prepay_id=" + prepay_id);
        parameters.put("signType", "MD5");
        parameters.put("timeStamp", timestape);

        secondSign = createSign("UTF-8", parameters, "H5");
        return secondSign;
    }


    /**
     * 二次签名APP
     *
     * @param prepay_id
     * @param appid
     * @param nonce_str
     * @return
     */
    public static String createSecondSignAPP(String prepay_id, String appid, String mchid, String nonce_str,
                                             String timestape, String packageName) {
        String secondSign = "";
        SortedMap<Object, Object> parameters = new TreeMap<Object, Object>();
        parameters.put("appid", appid);
        parameters.put("noncestr", nonce_str);
        parameters.put("package", packageName);
        parameters.put("partnerid", mchid);
        parameters.put("prepayid", prepay_id);
        parameters.put("timestamp", timestape);

        secondSign = createSign("UTF-8", parameters, "APP");
        return secondSign;
    }

    /**
     * 微信支付签名算法sign
     *
     * @param characterEncoding
     * @param parameters
     * @return
     */
    @SuppressWarnings("rawtypes")
    public static String createSign(String characterEncoding, SortedMap<Object, Object> parameters, String type) {
        StringBuffer sb = new StringBuffer();
        Set es = parameters.entrySet();// 所有参与传参的参数按照accsii排序（升序）
        Iterator it = es.iterator();
        while (it.hasNext()) {
            Map.Entry entry = (Map.Entry) it.next();
            String k = (String) entry.getKey();
            Object v = entry.getValue();
            if (null != v && !"".equals(v) && !"sign".equals(k) && !"key".equals(k)) {
                sb.append(k + "=" + v + "&");
            }
        }
        if (type.equals("APP")) {
            sb.append("key=" + Const.APP);
        } else if (type.equals("H5")) {
            sb.append("key=" + Const.WECHAT);
        }
        System.out.println("字符串拼接后是：" + sb.toString());
        String sign = MD5Encode(sb.toString(), characterEncoding).toUpperCase();
        return sign;
    }

    public static String MD5Encode(String origin, String charsetname) {
        String resultString = null;
        try {
            resultString = new String(origin);
            MessageDigest md = MessageDigest.getInstance("MD5");
            if (charsetname == null || "".equals(charsetname))
                resultString = byteArrayToHexString(md.digest(resultString
                        .getBytes()));
            else
                resultString = byteArrayToHexString(md.digest(resultString
                        .getBytes(charsetname)));
        } catch (Exception exception) {
        }
        return resultString;
    }

    private static String byteArrayToHexString(byte b[]) {
        StringBuffer resultSb = new StringBuffer();
        for (int i = 0; i < b.length; i++)
            resultSb.append(byteToHexString(b[i]));

        return resultSb.toString();
    }

    private static String byteToHexString(byte b) {
        int n = b;
        if (n < 0)
            n += 256;
        int d1 = n / 16;
        int d2 = n % 16;
        return hexDigits[d1] + hexDigits[d2];
    }

    private static final String hexDigits[] = {"0", "1", "2", "3", "4", "5",
            "6", "7", "8", "9", "a", "b", "c", "d", "e", "f"};

    public static String getRandomString(int length) { //length表示生成字符串的长度
        String base = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
        Random random = new Random();
        StringBuffer sb = new StringBuffer();
        int number = 0;
        for (int i = 0; i < length; i++) {
            number = random.nextInt(base.length());
            sb.append(base.charAt(number));
        }
        return sb.toString();
    }


    public static String toStackTrace(Throwable e) {
        StringWriter sw = new StringWriter();
        PrintWriter pw = new PrintWriter(sw);

        try {
            e.printStackTrace(pw);
            return sw.toString();
        } catch (Exception e1) {
            return "";
        }
    }

    /**
     * 解析微信回调后参数解析 解析的时候自动去掉CDMA
     *
     * @param xml
     */
    public static HashMap getWXPayResultV2(String xml) {
        HashMap weChatModel = new HashMap();
        try {
            StringReader read = new StringReader(xml);
            // 创建新的输入源SAX 解析器将使用 InputSource 对象来确定如何读取 XML 输入
            InputSource source = new InputSource(read);
            // 创建一个新的SAXBuilder
            SAXBuilder sb = new SAXBuilder();
            // 通过输入源构造一个Document
            Document doc;
            doc = (Document) sb.build(source);
            Element root = doc.getRootElement();// 指向根节点
            List<Element> list = root.getChildren();
            if (list != null && list.size() > 0) {
                for (Element element : list) {
                    weChatModel.put(element.getName(), element.getText());
                }
            }

        } catch (Exception e) {
            e.printStackTrace();
        }

        return weChatModel;
    }

    public static Object parsePageSize(Object object, Class tClass) {
        HashMap map = JSON.parseObject(JSON.toJSONString(object), HashMap.class);
        if (map.get("page") != null && map.get("size") != null) {
            map.put("page", Integer.parseInt(map.get("page").toString()) <= 0 ? 0 : (Integer.parseInt(map.get("page").toString()) - 1) * Integer.parseInt(map.get("size").toString()));
            return JSON.parseObject(JSON.toJSONString(map), tClass);
        }
        return object;
    }

    public synchronized static int getAutoIncId() {
        return id++;
    }

    public static void main(String[] args) {
        EduNotice eduNotice = new EduNotice();
        eduNotice.setPage(3);
        eduNotice.setSize(10);
        eduNotice = (EduNotice) parsePageSize(eduNotice, EduNotice.class);
        System.out.println(JSON.toJSONString(eduNotice));
    }
}
