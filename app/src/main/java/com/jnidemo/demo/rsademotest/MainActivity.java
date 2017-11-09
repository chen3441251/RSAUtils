package com.jnidemo.demo.rsademotest;

import android.os.Bundle;
import android.os.Environment;
import android.support.v7.app.AppCompatActivity;
import android.util.Log;

import com.jnidemo.demo.rsademotest.utils.RSAUtil;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;

public class MainActivity extends AppCompatActivity {
    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        setContentView(R.layout.activity_main);

        String enty =
                "找到你想要表达的主控思想，中篇在设计上人物不需要很多，简单的几个就好，主控思想也要简单明了，在故事的安排上几个简单的事件，不用太曲折，前面做些铺垫，表现人物性格，最后来个高潮，表现主题。最近也在学者写作。对这方面做了些研究。例子：阿Q正传，前一章是对人物的介绍，后面几章是通过一些事件来表达人物性格，阿Q想让自己姓赵，往自己脸上贴金，如同我们觉得和那个明星同姓，就觉得自己很高兴一样。阿Q赌钱，说明他希望不劳而获等等，他一节表现一个特征，然后再末尾带着下节提示，让人读起来环环相扣。副带的人物，只是为了符合主人公特性而塑造的。赵大爷，小D，假洋鬼子，最后的举人，和把总。鲁迅在人物设计上对于中国人的特性观察很入微，包括现在我们还能感觉得到特性。他最后想表达是无知带来的毁灭，所以阿Q稀里糊涂的就被当作替死鬼给干掉。我觉中国没有进步多半也是因为无知。你想要写小说，那么你的知识量需要足够，懂得多了你才有想说的。      这是这段时间研究的总结，我也是刚开始学，我怕我的答案不好，害了你，所以推荐一本书，编剧的艺术，去看看吧。最后还是要多读些故事学构架，也要学一些心理学。把你的人物表现的微妙微翘。";


        /**
         * 公钥加密私钥解密
         * */
        String s1 = RSAUtil.encryptByPublicKeyForSpilt(enty);
        Log.d("xxx", "公钥加密==" + s1);
        try {
            String s = RSAUtil.decryptByPrivateKeyForSpilt(s1);
            Log.d("xxx", "私钥解密==" + s);

        } catch (Exception e) {
            e.printStackTrace();
        }


        // 私钥加密公钥解密

        try {
            String s2 = RSAUtil.encryptByPrivateKeyForSpilt(enty);
            String s3 = RSAUtil.decryptByPublicKeyForSpilt(s2);
            Log.d("xxx", "公钥解密==" + s3);

        } catch (Exception e) {
            e.printStackTrace();
        }

    }

    //加密字符串过长写到本地
    public void storeData(String s) {
        File text123 = new File(Environment.getExternalStorageDirectory(), "RSAUtilsLog.txt");
        if (text123.exists()) {
            text123.delete();
        }
        FileOutputStream out = null;
        try {
            out = new FileOutputStream(text123);
            out.write(s.getBytes());
        } catch (Exception e) {
            e.printStackTrace();
        } finally {
            if (out != null) {
                try {
                    out.close();
                } catch (IOException e) {
                    e.printStackTrace();
                }
            }
        }
    }
}


