package org.example.utils;

import lombok.Builder;
import lombok.Data;
import lombok.ToString;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.*;

public class JsonUtils {
    public static String replaceDoubleQuote(String raw, char replacement) {
        if (null == raw || raw.isEmpty()) {
            return raw;
        }
        boolean isWrapper = false;
        if (raw.charAt(0) != '{') {
            StringBuilder wrapper = new StringBuilder();
            wrapper.append("{").append(raw).append("}");
            raw = wrapper.toString();
            isWrapper = true;
        }

        char[] copyCharArray = raw.toCharArray();
        int length = raw.length();
        Boolean[] flag = new Boolean[length];
        match(copyCharArray, flag, 0);
        for (int i = 0; i < length; i++) {
            if (Boolean.FALSE == flag[i]) {
                copyCharArray[i] = replacement;
            }
        }
        String res = new String(copyCharArray);

        if (isWrapper) {
            res = res.substring(1, res.length() - 1);
        }
        return res;
    }

    /**
     *  json引号无嵌套合法形式 {"x":"x","y":y,"z":"z"}
     *  json引号有嵌套合法形式 {"x":"x","y":{"y1":y1,"y2":"y2"},"z":{"z1":"z1"}}
     *  //引号匹配规则 {"与":匹配、,"与":匹配、":"与","匹配、":"与"}匹配
     *  引号匹配规则 {"与":匹配、,"与":匹配、:"与",匹配、:"与"}匹配
     *  先校验合法性，再进行左右匹配
     *  总是由right来匹配已存在的left，如果right先于left存在则为非法
     *  外层优先规则：如果存在多个相同且合法的双引号，那么总是先匹配最外层的双引号，剩下的视为非法
     *  邻接匹配规则：任何邻接匹配的双引号之间存在的引号均视为非法字符
     *  键匹配规则：任何键左右引号之间不会存在其他引号，如果存在则该键左右引号一定为值的一部分
     *  left1({")邻接匹配right1(":)
     *  left2(,")邻接匹配right1(":)
     *  left3(:")邻接匹配right2(",)
     *  left3(:")邻接匹配right3("})
     *  (新增)非法传递规则：如果左引号最近的引号非法，则必非法，且与之匹配的键右引号一定为非法(值右引号则不一定)
     *  (新增)右值回溯规则：如果右值引号最近的引号不是左值引号，则需要回溯到最近的合法的左值引号，它们之间的所有引号皆非法
     *                  (在合法的json中，右值引号无论是否合法，总能找到左值引号)
     *  一个键值对为一个匹配轮次，下一个键匹配成功后上一个键值匹配轮次才算完成
     *  测试用例：{"x":"xxx,"yy":zzz"}，{"x":"xxx",yy":zzz"}，{"x":"xxx",yy:"zzz"}，{"x":"xxx"}x"}，
     *       {"a":a,"x":"xxx"},"yy:"uu,"t":z",zz","b":"b"}，{"a":a,"x":"xxx"},"yy:"uu,"t":z","zz","b":"b"}，
     *       {"a":a,"x":"xxx"},"yy:"uu,"t":z","zy":zyx","b":"b"}，{"a":a,"x":"x"},"y:"y","t":t","z":z","b":"b"}，
     *       {"x":"x"},"y:"u","z":z","b":"b"}，{"a":"{"b":"b"}"}，
     *       {"a":""b":"b","c":"c""}(?)，{"a":""b":"b","c":""d":"d","e":"e"""}(?)
     */
    public static void match(char[] raw, Boolean[] flag, int startIndex) {
        int length = raw.length;
        if (startIndex >= length - 1) {
            return;
        }
        // 用于统计未匹配的引号数，代替栈，每读取一个合法左引号+1，每匹配上一个合法右引号-1
        int depthDiff = 0;
        // 用于匹配键值对引号
        Deque<DoubleQuote> kvStack = new ArrayDeque<>();
        // 记录全部引号
        Deque<DoubleQuote> fullStack = new ArrayDeque<>();
        for (int i = startIndex; i < length - 1; i++) {
            if ('"' == raw[i]) {
                DoubleQuote curDq;
                if ((curDq = isLegalDoubleQuote(raw, i)).getStatus() != -1) {
                    // 判断depthDiff和kvStack
                    if (0 == depthDiff && kvStack.isEmpty()) {
                        // 未开始匹配或者不存在未匹配上的引号
                        // 如果为左引号，则入栈
                        if (curDq.isLeft) {
                            // 根据“非法传递规则”查找上一个引号是否合法
                            if (!fullStack.isEmpty() && fullStack.peek().getStatus() == -1) {
                                flag[i] = Boolean.FALSE;
                                curDq.setStatus(-1);
                                continue;
                            }
                            depthDiff++;
                            kvStack.addFirst(curDq);
                        } else {
                            if (curDq.isKey) {
//                                System.out.println("73:" + i + ",dq:" + curDq);
                                // 如果右键引号不存在可匹配的左键引号，则视为为非法
                                flag[i] = Boolean.FALSE;
                                curDq.setStatus(-1);
                            } else {
                                // 根据右值回溯规则，右值引号回溯到最近的一个合法左值引号，并将它们之前的引号设置非法
                                Deque<DoubleQuote> copyStack = new ArrayDeque<>(fullStack);
                                while (!copyStack.isEmpty()) {
                                    DoubleQuote traceDq = copyStack.pop();
                                    if (traceDq.getType() == DoubleQuoteType.LEFT_VALUE_START && traceDq.getStatus() != -1) {
                                        depthDiff--;
                                        if (!kvStack.isEmpty() && traceDq == kvStack.peek()) kvStack.pop();
                                        break;
                                    }
                                    if (flag[traceDq.getIndex()] != Boolean.FALSE) {
                                        depthDiff = traceDq.isLeft ? depthDiff - 1 : depthDiff + 1;
                                    }
                                    traceDq.setStatus(-1);
//                                    System.out.println("100:" + i + ",dq:" + traceDq);
                                    flag[traceDq.getIndex()] = Boolean.FALSE;
                                    traceDq.setStatus(-1);
                                }
                            }
                        }
                    } else if (!kvStack.isEmpty()) {
                        DoubleQuote preDq = kvStack.peek();
                        if (depthDiff == 0) {
                            // 暂无未匹配的引号的情况
                            if (preDq.isLeft) {
                                // todo
                            } else {
                                if (curDq.isLeft) {
                                    // 入栈
                                    depthDiff++;
                                    kvStack.addFirst(curDq);
                                } else {
                                    if (curDq.isKey) {
//                                        System.out.println("90:" + i + ",dq:" + curDq);
                                        // 该情况下只可能出现在值中，出现键右引号则为非法
                                        flag[i] = Boolean.FALSE;
                                        curDq.setStatus(-1);
                                    } else {
                                        // 根据外层优先规则，回溯到最近一个可与curDq匹配上的引号；同时根据邻接匹配规则，之间的引号视为非法
                                        DoubleQuote traceDq = null;
                                        while (!kvStack.isEmpty()) {
                                            traceDq = kvStack.pop();
                                            if (!isMatchDoubleQuotes(traceDq, curDq)) {
                                                traceDq.setStatus(-1);
                                                depthDiff = traceDq.isLeft ? depthDiff - 1 : depthDiff + 1;
//                                                System.out.println("100:" + i + ",dq:" + traceDq);
                                                flag[traceDq.getIndex()] = Boolean.FALSE;
                                                traceDq.setStatus(-1);
                                            }
                                        }
                                    }
                                }
                            }
                        } else {
                            // 存在未匹配的引号的情况
                            if (preDq.isLeft) {
                                // 判断是否匹配
                                if (isMatchDoubleQuotes(preDq, curDq)) {
                                    preDq.setStatus(1);
                                    curDq.setStatus(1);
                                    if (curDq.isKey) {
                                        // 如果当前匹配项为键，则上一轮次的键值引号匹配确认完成，清除kvStack中已匹配上的引号
                                        while (kvStack.size() > 0) {
                                            DoubleQuote dq = kvStack.peek();
                                            if (dq.getStatus() == 1) {
                                                kvStack.pop();
                                            } else {
                                                System.out.println("引号:" + dq);
                                                break;
                                            }
                                        }
                                    } else {
                                        // 如果当前匹配项为值，则入栈，等待下一轮次的键引号匹配结果
                                        kvStack.addFirst(curDq);
                                    }
                                    depthDiff--;
                                } else {
                                    if (preDq.isKey) {
                                        // 根据键匹配规则，出现不能与键左引号匹配的情况一定在值的内部
                                        while (kvStack.size() > 0) {
                                            DoubleQuote traceDq = kvStack.peek();
                                            if (DoubleQuoteType.LEFT_VALUE_START != traceDq.getType()) {
                                                traceDq.setStatus(-1);
                                                kvStack.pop();
                                                depthDiff = traceDq.isLeft ? depthDiff - 1 : depthDiff + 1;
//                                                System.out.println("138:" + i + ",dq:" + traceDq);
                                                flag[traceDq.getIndex()] = Boolean.FALSE;
                                                traceDq.setStatus(-1);
                                            } else {
                                                if (isMatchDoubleQuotes(traceDq, curDq)) {
                                                    // 如果当前匹配项为值，则入栈，等待下一轮次的键引号匹配结果
                                                    kvStack.addFirst(curDq);
                                                    depthDiff--;
                                                } else {
                                                    // 根据邻接匹配规则，不能与左引号匹配则为非法引号
//                                                    System.out.println("147:" + i + ",dq:" + curDq);
                                                    flag[i] = Boolean.FALSE;
                                                    curDq.setStatus(-1);
                                                }
                                                break;
                                            }
                                        }
                                    } else {
                                        // 根据邻接匹配规则，不能与左引号匹配则为非法引号
//                                        System.out.println("155:" + i + ",dq:" + curDq);
                                        flag[i] = Boolean.FALSE;
                                        curDq.setStatus(-1);
                                    }
                                }
                            } else {
                                // 正常情况下不会执行到这里
                                System.out.println("error!!!");
                            }
                        }

                    }
                } else {
//                    System.out.println("166:" + i + ",dq:" + curDq);
                    flag[i] = Boolean.FALSE;
                    curDq.setStatus(-1);
                    DoubleQuote preDq = null;
                    int count = 1;
                    // 如果非法引号的上一个引号不是左值引号:"，则均视为非法引号
                    while (kvStack.size() > 0) {
                        DoubleQuote traceDq = kvStack.peek();
                        if (1 == count) {
                            preDq = traceDq;
                            count--;
                        }
                        if (DoubleQuoteType.LEFT_VALUE_START != traceDq.getType()) {
                            traceDq.setStatus(-1);
                            kvStack.pop();
                            depthDiff = traceDq.isLeft ? depthDiff - 1 : depthDiff + 1;
//                            System.out.println("181:" + i + ",dq:" + traceDq);
                            flag[traceDq.getIndex()] = Boolean.FALSE;
                            traceDq.setStatus(-1);
                        } else {
                            // 找到最近的一个左值引号为止
//                            if (!preDq.isLeft) {
//                                // 如果kvStack中最新的引号是右引号，则未匹配的引号数+1
//                                depthDiff++;
//                            }
                            break;
                        }
                    }
                }
                fullStack.push(curDq);
//                System.out.println("depthDiff:" + depthDiff);
            }
        }
    }

    private static boolean isMatchDoubleQuotes(DoubleQuote preDq, DoubleQuote curDq) {
        if (null == preDq || null == curDq) {
            return false;
        }
        return Optional.ofNullable(DoubleQuoteType.matchRule.get(preDq.getType())).orElse(new HashSet<>()).contains(curDq.getType());
    }

    private static DoubleQuote isLegalDoubleQuote(char[] raw, int i) {
        if (0 == i || i >= raw.length - 1) {
            return DoubleQuote.builder()
                    .index(i)
                    .status(-1)
                    .build();
        }
        // 左引号合法形式 {"  ,"  ":"
        if ('{' == raw[i - 1]) {
            return DoubleQuote.builder()
                    .type(DoubleQuoteType.LEFT_KEY_INITIAL)
                    .index(i)
                    .isLeft(true)
                    .isKey(true)
                    .build();
        } else if (',' == raw[i - 1]) {
            return DoubleQuote.builder()
                    .type(DoubleQuoteType.LEFT_KEY_START)
                    .index(i)
                    .isLeft(true)
                    .isKey(true)
                    .build();
        } else if (i > 1 && '"' == raw[i - 2] && ':' == raw[i - 1]) {
            return DoubleQuote.builder()
                    .type(DoubleQuoteType.LEFT_VALUE_START)
                    .index(i)
                    .isLeft(true)
                    .isKey(false)
                    .build();
        }
        // 右引号合法形式 ":  ","  "}
        if (':' == raw[i + 1]) {
            return DoubleQuote.builder()
                    .type(DoubleQuoteType.RIGHT_KEY_END)
                    .index(i)
                    .isLeft(false)
                    .isKey(true)
                    .build();
        } else if ('}' == raw[i + 1]) {
            return DoubleQuote.builder()
                    .type(DoubleQuoteType.RIGHT_VALUE_FINAL)
                    .index(i)
                    .isLeft(false)
                    .isKey(false)
                    .build();
        } else if (i < raw.length - 2 && ',' == raw[i + 1] && '"' == raw[i + 2]) {
            return DoubleQuote.builder()
                    .type(DoubleQuoteType.RIGHT_VALUE_END)
                    .index(i)
                    .isLeft(false)
                    .isKey(false)
                    .build();
        }
        return DoubleQuote.builder()
                .index(i)
                .status(-1)
                .build();
    }



    @Builder
    @ToString
    @Data
    static class DoubleQuote {
        DoubleQuoteType type;
        // 下标
        int index;
        // 状态 -1非法，1已匹配待消除，2可消除
        int status;
        // 是否为左引号
        boolean isLeft;
        // 是否为键引号
        boolean isKey;

    }

    enum DoubleQuoteType {
        LEFT_KEY_INITIAL("{\""),
        LEFT_KEY_START(",\""),
        LEFT_VALUE_START(":\""),

        RIGHT_VALUE_FINAL("\"}"),
        RIGHT_KEY_END("\":"),
        RIGHT_VALUE_END("\","),
        ;

        DoubleQuoteType(String text) {
            this.text = text;
        }

        private final String text;

        public static HashMap<DoubleQuoteType, Set<DoubleQuoteType>> matchRule =
                new HashMap<DoubleQuoteType, Set<DoubleQuoteType>>(){
                    {
                        put(LEFT_KEY_INITIAL, new HashSet<>(Arrays.asList(RIGHT_KEY_END)));
                        put(LEFT_KEY_START, new HashSet<>(Arrays.asList(RIGHT_KEY_END)));
                        put(LEFT_VALUE_START, new HashSet<>(Arrays.asList(RIGHT_VALUE_FINAL, RIGHT_VALUE_END)));
                    }
                };
    }

    public static void main(String[] args) {

        String str = readFile("C:\\Users\\zdhe9\\Documents\\CSIPClient\\Chat\\zdhe\\recvFile\\t_m00_customer返回的原始报文1.txt");
//        String str = readFile("C:\\Users\\zdhe9\\Documents\\CSIPClient\\Chat\\zdhe\\recvFile\\非json.txt");
//        str.replaceAll("\\s*|\r|\n", "");
//        str = str.substring(1, str.length() - 1);
//        str = str.replaceAll("\\\\", "");
        String newStr = replaceDoubleQuote(str, '”');
//        JSONObject resultJson = JSONParser.parseObject(newStr);
        System.out.println(newStr);
    }

    public static String readFile(String path) {
        //防止文件建立或读取失败，用catch捕捉错误并打印，也可以throw;
        //不关闭文件会导致资源的泄露，读写文件都同理
        //Java7的try-with-resources可以优雅关闭文件，异常时自动关闭文件；详细解读https://stackoverflow.com/a/12665271
        StringBuilder sb = new StringBuilder();
        try (FileReader reader = new FileReader(path);
             BufferedReader br = new BufferedReader(reader) // 建立一个对象，它把文件内容转成计算机能读懂的语言
        ) {
            String line;
            //网友推荐更加简洁的写法
            while ((line = br.readLine()) != null) {
                // 一次读入一行数据
                sb.append(line);
            }
        } catch (IOException e) {
            e.printStackTrace();
        }
        return sb.toString();
    }
}
