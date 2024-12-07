package com.leo.springbootinit.aop;


import com.leo.springbootinit.annotation.AuthCheck;
import com.leo.springbootinit.service.UserService;
import org.aspectj.lang.ProceedingJoinPoint;
import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;
import org.springframework.stereotype.Component;
import org.springframework.web.context.request.RequestAttributes;
import org.springframework.web.context.request.RequestContextHolder;
import org.springframework.web.context.request.ServletRequestAttributes;

import javax.annotation.Resource;
import javax.servlet.http.HttpServletRequest;

/**
 * 权限校验 AOP
 *
 */
@Aspect
@Component
public class AuthInterceptor {

    @Resource
    private UserService userService;

    /**
     * 执行拦截
     *
     * @param joinPoint
     * @param authCheck
     * @return
     */
    @Around("@annotation(authCheck)")
    public Object doInterceptor(ProceedingJoinPoint joinPoint, AuthCheck authCheck) throws Throwable {
        String mustRole = authCheck.mustRole();
        RequestAttributes requestAttributes = RequestContextHolder.currentRequestAttributes();
        HttpServletRequest request = ((ServletRequestAttributes) requestAttributes).getRequest();
        // 当前登录用户
        com.leo.springbootinit.model.entity.User loginUser = userService.getLoginUser(request);
        com.leo.springbootinit.model.enums.UserRoleEnum mustRoleEnum = com.leo.springbootinit.model.enums.UserRoleEnum.getEnumByValue(mustRole);
        // 不需要权限，放行
        if (mustRoleEnum == null) {
            return joinPoint.proceed();
        }
        // 必须有该权限才通过
        com.leo.springbootinit.model.enums.UserRoleEnum userRoleEnum = com.leo.springbootinit.model.enums.UserRoleEnum.getEnumByValue(loginUser.getUserRole());
        if (userRoleEnum == null) {
            throw new com.leo.springbootinit.exception.BusinessException(com.leo.springbootinit.common.ErrorCode.NO_AUTH_ERROR);
        }
        // 如果被封号，直接拒绝
        if (com.leo.springbootinit.model.enums.UserRoleEnum.BAN.equals(userRoleEnum)) {
            throw new com.leo.springbootinit.exception.BusinessException(com.leo.springbootinit.common.ErrorCode.NO_AUTH_ERROR);
        }
        // 必须有管理员权限
        if (com.leo.springbootinit.model.enums.UserRoleEnum.ADMIN.equals(mustRoleEnum)) {
            // 用户没有管理员权限，拒绝
            if (!com.leo.springbootinit.model.enums.UserRoleEnum.ADMIN.equals(userRoleEnum)) {
                throw new com.leo.springbootinit.exception.BusinessException(com.leo.springbootinit.common.ErrorCode.NO_AUTH_ERROR);
            }
        }
        // 通过权限校验，放行
        return joinPoint.proceed();
    }
}

