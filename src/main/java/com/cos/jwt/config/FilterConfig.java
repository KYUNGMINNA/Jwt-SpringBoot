package com.cos.jwt.config;

import com.cos.jwt.filter.MyFilter1;
import com.cos.jwt.filter.MyFilter2;
import com.cos.jwt.filter.MyFilter3;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

import javax.servlet.FilterRegistration;

//굳이 시큐리티 필터에 연결하지 않고 , 직접 필터를 만들어서 필터 적용시키는 방법 !!!
//시큐리티 필터가 먼저 동작하고 여기 필터들이 동작함 !!!!!!!!!!!!!!!!!!!!!!
//시큐리티 필터 체인이 내가 만든 필터보다 먼저 동작함
@Configuration
public class FilterConfig {

    @Bean
    public FilterRegistrationBean<MyFilter1> filter1(){
        //필터 제작
        FilterRegistrationBean<MyFilter1> bean=new FilterRegistrationBean<>(new MyFilter1());
        bean.addUrlPatterns("/*");
        bean.setOrder(0); //낮은 번호가 필터중에서 가장 먼저 실행됨

        return bean;
    }

    @Bean
    public FilterRegistrationBean<MyFilter2> filter2(){
        FilterRegistrationBean<MyFilter2> bean2=new FilterRegistrationBean<>(new MyFilter2());
        bean2.addUrlPatterns("/*");
        bean2.setOrder(1); //낮은 번호가 가장 먼저 실행됨
        return bean2;
    }

}
