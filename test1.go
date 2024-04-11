package main

import (
	"fmt"
    "net/http"
	"net/mail"
	"time"

    "github.com/gin-gonic/gin"
	"gorm.io/driver/mysql"
	"gorm.io/gorm"
    "github.com/golang-jwt/jwt/v5"
)

type UserInfo struct {
	ID       int    `form:"id"`
	Name     string `form:"name" binding:"required"`
	Email    string `form:"email" binding:"required,email"`
	Password string `form:"password" binding:"required,min=6"`
}

// 创建一个 JWT（JSON Web Token）字符串。
// JWT 是一种用于在网络应用之间安全传递声明的开放标准。

var jwtKey = []byte("my_secret_key")	// 用于签名和验证 JWT 的密钥

// input: email || output:string,error
func createToken(email string) (string, error) {
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"email": email,
		"exp":   time.Now().Add(time.Minute * 10).Unix(), // 有效时长10分钟
	})

	return token.SignedString(jwtKey)
}

func validateToken(tokenString string) (*jwt.Token, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("Unexpected signing method: %v", token.Header["alg"])
		}
		return jwtKey, nil
	})

	if err != nil {
		return nil, err
	}

	if _, ok := token.Claims.(jwt.MapClaims); !ok || !token.Valid {
		return nil, fmt.Errorf("bad token.")
	}

	return token, nil
}

func validateCookie(c *gin.Context) (*jwt.Token, error) {
	tokenString, err := c.Cookie("gin_cookie")
	if err != nil {
		return nil, err
	}
	token, err := validateToken(tokenString)
	if err != nil {
		return nil, err
	}
	return token, nil
}

func main() {
    // 创建一个默认的 Gin 路由器
    r := gin.Default()

    r.POST("/api/register", create)  // 创建一个路由，允许用户提交新账户信息
	r.POST("/api/login", login)		// 新增路由，允许用户通过提供电子邮件和密码来检索其帐户信息,相当于登陆
	r.POST("/api/update", update) // 新增的路由，用于更新用户信息
	r.POST("/api/delete",delete)	// 删除用户信息
	r.POST("/api/show_all",show_all)	// 显示用户信息

    // 启动 Gin 服务器，默认监听在 8001 端口
    r.Run(":8001")
}

// isValidEmail 检查电子邮件格式是否正确
func isValidEmail(email string) bool {
    _, err := mail.ParseAddress(email)
	// 如果解析正确，err会变为nil
	return err == nil
}

func create(c *gin.Context) {
	// 绑定请求体到 UserInfo 结构体类型的form 
	var form UserInfo
	if err := c.ShouldBindJSON(&form); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 检查电子邮件格式是否正确
	if !isValidEmail(form.Email) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email format"})
		return
	}

	// 打开数据库，3306是MySQL默认端口
	dsn := "root:123456@tcp(127.0.0.1:3306)/gobase"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// check whether the name exists.
	var user UserInfo
	db.Table("account").Where("name = ?", form.Name).First(&user)
	if (user != UserInfo{}) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "name exists!"})
		return
	}

	// check whether the email has been used.
	db.Table("account").Where("email = ?", form.Email).First(&user)
	if (user != UserInfo{}) {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("email %s has been used!", form.Email)})
		return
	}

	// 保存用户到数据库(:= 对于没有声明的变量会自动声明)
	user = UserInfo{Name: form.Name, Email: form.Email, Password: form.Password}
	result := db.Table("account").Create(&user)
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": result.Error})
		return
	}
	
	
	// 这里只是返回成功消息
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Account %s created successfully!",user.Name)})
}

func login(c *gin.Context) {
	email := c.Query("email")
	password := c.Query("password")

	// 打开数据库
	dsn := "root:123456@tcp(127.0.0.1:3306)/gobase"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 查询数据库中是否存在匹配的用户记录
	var user UserInfo
	result := db.Table("account").Where("email = ? AND password = ?", email, password).First(&user)
	if result.Error != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("Invalid email:%s or password:%s",email,password)})
		return
	}

	// Create the JWT string.
	token, err := createToken(user.Email)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to create token"})
		return
	}
	// tell the user it's ok. 3600 是最大存活时间1h
	c.SetCookie("gin_cookie", token, 3600, "/", "", false, true)

	// 返回匹配的用户信息
	c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Welcom user %s !", user.Name)})
}

func update(c *gin.Context) {
    token, err := validateCookie(c)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// get email from cookie
	email := token.Claims.(jwt.MapClaims)["email"]
	// new password
	password := c.Query("password")
	name := c.Query("name")
	// update
	dsn := "root:123456@tcp(127.0.0.1:3306)/gobase"
	db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}
	// retrieve the user by email.
	var user UserInfo
	db.Table("account").Where("email = ?", email).First(&user)
	if (user == UserInfo{}) {
		c.JSON(http.StatusBadRequest, gin.H{"error": "this email has not been registered."})
		return
	}

    // 更新用户信息
	if name != "" {
		user.Name = name
	}
	if password != "" {
		user.Password = password
	}

    // 保存更新后的用户信息到数据库
    if err := db.Table("account").Save(&user).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to update user"})
        return
    }

    // 返回更新成功的消息
    c.JSON(http.StatusOK, gin.H{"message": "User information updated successfully"})
}

func delete(c *gin.Context) {
	email := c.Query("email")
	password := c.Query("password")

	// 打开数据库
    dsn := "root:123456@tcp(127.0.0.1:3306)/gobase"
    db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
    if err != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
        return
    }

    // 查询数据库中是否存在匹配的用户记录
    var user UserInfo
    result := db.Table("account").Where("email = ? AND password = ?", email, password).First(&user)
    if result.Error != nil {
        c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid email or password"})
        return
    }

    // 删除用户账户
    if err := db.Table("account").Delete(&user).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to delete account"})
        return
    }

    // 返回删除成功的消息
    c.JSON(http.StatusOK, gin.H{"message": fmt.Sprintf("Account %s deleted successfully",user.Name)})
}

func show_all(c *gin.Context) {
	if _, err := validateCookie(c); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// 打开数据库
    dsn := "root:123456@tcp(127.0.0.1:3306)/gobase"
    db, err := gorm.Open(mysql.Open(dsn), &gorm.Config{})
    if err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
        return
    }

    // 查询数据库，获取所有帐户列表
    var accountNames []string
    if err := db.Table("account").Pluck("name", &accountNames).Error; err != nil {
        c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to retrieve accounts"})
        return
    }

    // 返回帐户列表给客户端
    c.JSON(http.StatusOK, accountNames)
}