package com.sensej.web;

import com.google.common.collect.ImmutableList;
import com.sensej.domain.Role;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.authentication.AuthenticationManager;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder;
import org.springframework.security.web.authentication.WebAuthenticationDetails;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.RequestMethod;
import org.springframework.web.bind.annotation.RequestParam;
import com.sensej.domain.User;
import com.sensej.persistence.UserDao;

import javax.servlet.http.HttpServletRequest;
import javax.websocket.server.PathParam;

@Controller
public class PageController {

    @Autowired
    private UserDao userDao;
    @Autowired
    AuthenticationManager authenticationManager;

    @RequestMapping("/login")
    public String getLogin(@RequestParam(value = "error", required = false) String error,
                           @RequestParam(value = "logout", required = false) String logout,
                           Model model) {
        model.addAttribute("error", error != null);
        model.addAttribute("logout", logout != null);
        return "login";
    }

    @RequestMapping(value = "/", method = RequestMethod.GET)
    public String mainPage() {
        return "index";
    }


    @RequestMapping(value = "/admin/admin", method = RequestMethod.GET)
    public String admin() {
        return "admin";
    }

    @RequestMapping(method = RequestMethod.GET, path = "/register")
    public String registerPage() {
        return "register";
    }

    @RequestMapping(method = RequestMethod.POST, path = "/register")
    public String register(@PathParam("username") String username,
                           @PathParam("password") String password,
                           HttpServletRequest request) {
        User byUsername = userDao.findByUsername(username).orElse(null);
        if (byUsername != null) {
            return "redirect:/register";
        }
        userDao.save(User.builder()
                .username(username)
                .password(new BCryptPasswordEncoder().encode(password))
                .authorities(ImmutableList.of(Role.USER))
                .accountNonExpired(true)
                .accountNonLocked(true)
                .credentialsNonExpired(true)
                .enabled(true)
                .build());

        UsernamePasswordAuthenticationToken token = new UsernamePasswordAuthenticationToken(username, password);

        request.getSession();

        token.setDetails(new WebAuthenticationDetails(request));
        Authentication authenticatedUser = authenticationManager.authenticate(token);

        SecurityContextHolder.getContext().setAuthentication(authenticatedUser);
        return "redirect:/";
    }

}
