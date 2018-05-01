package net.continuumsecurity.applications;

import net.continuumsecurity.Config;
import net.continuumsecurity.Credentials;
import net.continuumsecurity.UserPassCredentials;
import net.continuumsecurity.behaviour.ILogin;
import net.continuumsecurity.behaviour.ILogout;
import net.continuumsecurity.behaviour.INavigable;
import net.continuumsecurity.behaviour.ISimpleNavigable;
import net.continuumsecurity.web.WebApplication;
import org.openqa.selenium.By;
import org.openqa.selenium.support.ui.Select;

public class MobileIDApplication extends WebApplication implements ILogin,
        ILogout,INavigable,ISimpleNavigable {

    public MobileIDApplication() {
        super();

    }

    @Override
    public void openLoginPage() {

    }

    @Override
    public void login(Credentials credentials) {

    }

    public void sleep() {
        try {
            System.out.print("*** Started sleep *** \n");
            Thread.sleep(3000); //sleep for 3 seconds
            System.out.print("*** Ended Sleep *** \n");
        } catch (InterruptedException e) {
            System.out.println("got interrupted!");
        }
    }

    // Convenience method
    public void login(String username, String password) {
        login(new UserPassCredentials(username, password));
    }

    @Override
    public boolean isLoggedIn() {

        return false;
    }

    @Override
    public void logout() {
        driver.findElement(By.linkText("Logout")).click();
    }


    public void navigate() {
        driver.get(Config.getInstance().getBaseUrl() + "idcard");
        sleep();
        System.out.print("First step \n");
        driver.findElement(By.id("use-dl-btn")).click();
        driver.findElement(By.id("dlNum")).clear();
        driver.findElement(By.id("dlNum")).sendKeys("992893");
        driver.findElement(By.id("dob")).clear();
        driver.findElement(By.id("dob")).sendKeys("1987-08-05");
        driver.findElement(By.id("license-btn")).click();
        sleep();
        findAndWaitForElement(By.id("driver"));
        new Select(driver.findElement(By.id("driver"))).selectByVisibleText("JULIE VADERS-COLLINS");
        new Select(driver.findElement(By.id("vehicle"))).selectByVisibleText("2007 COBALT");
        driver.findElement(By.id("get-card-btn")).click();
        sleep();
        System.out.print("Second step \n");
        driver.findElement(By.id("start-over-btn")).click();
        driver.get(Config.getInstance().getBaseUrl() + "idcard");
        driver.findElement(By.id("use-policy-btn")).click();
        driver.findElement(By.id("policyNum")).clear();
        driver.findElement(By.id("policyNum")).sendKeys("AZSS104163051");
        driver.findElement(By.id("zip")).clear();
        driver.findElement(By.id("zip")).sendKeys("86327");
        driver.findElement(By.id("policy-btn")).click();
        findAndWaitForElement(By.id("driver"));
        new Select(driver.findElement(By.id("driver"))).selectByVisibleText("RONALD WYATT");
        new Select(driver.findElement(By.id("vehicle"))).selectByVisibleText("2006 SILVERADO");
        driver.findElement(By.id("get-card-btn")).click();    
    }

    public void simple_navigate() {

    }

}
