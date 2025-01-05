package main

import (
	"fmt"
	"log"
	"os"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"github.com/joho/godotenv"
	"gorm.io/driver/postgres"
	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

func authRequired(c *fiber.Ctx) error {
	cookie := c.Cookies("jwt")
	jwtSecretKey := os.Getenv("JWT_KEY")

	token, err := jwt.ParseWithClaims(cookie, jwt.MapClaims{}, func(token *jwt.Token) (interface{}, error) {
		return []byte(jwtSecretKey), nil
	})

	if err != nil || !token.Valid {
		return c.SendStatus(fiber.StatusUnauthorized)
	}

	claims := token.Claims.(jwt.MapClaims)
	fmt.Println(claims)

	if claims["role"].(string) != "admin" {
		return c.SendStatus(fiber.StatusForbidden)
	}

	return c.Next()
}

func main() {

	// Set Database Connection
	host := os.Getenv("DB_HOST")
	logPath := "/var/log/gorm.log"

	if host == "" {
		// Load .env file
		err := godotenv.Load()
		if err != nil {
			log.Println("Error loading .env file")
		} else {
			host = os.Getenv("DB_HOST")
			logPath = "./gorm.log"
		}
	}

	port, _ := strconv.Atoi(os.Getenv("DB_PORT"))
	user := os.Getenv("DB_USER")
	password := os.Getenv("DB_PASSWORD")
	dbname := os.Getenv("DB_NAME")

	// Database Connection
	dsn := fmt.Sprintf("host=%s port=%d user=%s "+
		"password=%s dbname=%s sslmode=disable",
		host, port, user, password, dbname)

	// Config Logger
	logFile, err := os.OpenFile(logPath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0666)
	if err != nil {
		panic(err)
	}
	defer logFile.Close()

	newLogger := logger.New(
		log.New(logFile, "", log.LstdFlags),
		logger.Config{
			SlowThreshold: time.Second,
			LogLevel:      logger.Info,
			Colorful:      false,
		},
	)

	// Connect Database
	db, err := gorm.Open(postgres.Open(dsn), &gorm.Config{
		Logger: newLogger,
	})

	if err != nil {
		panic("failed to connect to database")
	}

	// Migrate Database
	db.AutoMigrate(&User{})
	fmt.Println("Database migration completed!")
	createAdminUser(db)

	// SetUp Fiber
	app := fiber.New()
	// app.Use(cors.New(cors.Config{
	// 	AllowOrigins:     os.Getenv("ALLOW_ORIGIN"),
	// 	AllowCredentials: true,
	// 	AllowMethods:     "GET,POST,PUT,DELETE",
	// 	AllowHeaders:     "Origin, Content-Type, Accept, Authorization",
	// 	MaxAge:           3600,
	// }))

	apiGroup := app.Group("/api/v1")
	apiGroup.Use("/users", authRequired)

	apiGroup.Post("/register", func(c *fiber.Ctx) error {
		return register(db, c)
	})

	apiGroup.Post("/login", func(c *fiber.Ctx) error {
		return login(db, c)
	})

	apiGroup.Get("/users", func(c *fiber.Ctx) error {
		return listUser(db, c)
	})

	apiGroup.Get("/users/:id", func(c *fiber.Ctx) error {
		return getUser(db, c)
	})

	apiGroup.Patch("/users/:id", func(c *fiber.Ctx) error {
		return updateUser(db, c)
	})

	apiGroup.Delete("/users/:id", func(c *fiber.Ctx) error {
		return deleteUser(db, c)
	})

	app.Listen(":3000")
}
