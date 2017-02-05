package com.sample;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

@Controller
public class ErrorController {
  @RequestMapping("/unauthenticated")
  public String unauthenticated() {
    return "redirect:/?error=true";
  }
}