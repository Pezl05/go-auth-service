package main

import (
	"log"
	"os"
	"strconv"
	"time"

	"github.com/gofiber/fiber/v2"
	"github.com/golang-jwt/jwt/v4"
	"golang.org/x/crypto/bcrypt"
	"gorm.io/gorm"
)

type User struct {
	UserID    uint           `gorm:"primaryKey;autoIncrement" json:"user_id"`
	Username  string         `gorm:"size:50;uniqueIndex:idx_users_username;not null" json:"username"`
	Email     string         `gorm:"size:100;uniqueIndex:idx_users_email;not null" json:"email"`
	Password  string         `gorm:"size:255;not null" json:"password"`
	FullName  *string        `gorm:"size:100;not null" json:"full_name,omitempty"`
	Role      string         `gorm:"size:50;default:'member'" json:"role"`
	CreatedAt time.Time      `gorm:"autoCreateTime" json:"created_at"`
	UpdatedAt time.Time      `gorm:"autoUpdateTime" json:"updated_at"`
	DeletedAt gorm.DeletedAt `gorm:"index" json:"deleted_at,omitempty"`
}

func register(db *gorm.DB, c *fiber.Ctx) error {
	var user User
	if err := c.BodyParser(&user); err != nil {
		return c.SendStatus(fiber.StatusBadRequest)
	}

	// Encrypt Password
	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(user.Password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		return err
	}

	// Create user
	user.Password = string(hashedPassword)
	result := db.Create(&user)
	if result.Error != nil {
		return c.SendStatus(fiber.StatusBadRequest)
	}

	return c.JSON(fiber.Map{
		"message": "Register Successful",
	})
}

func login(db *gorm.DB, c *fiber.Ctx) error {
	var inputUser User
	var user User
	if err := c.BodyParser(&inputUser); err != nil {
		return c.SendStatus(fiber.StatusBadRequest)
	}

	// Search User from Username or Email
	result := db.Where(
		"username = ? OR email = ?",
		inputUser.Username, inputUser.Username,
	).First(&user)

	if result.Error != nil {
		return c.SendStatus(fiber.StatusUnauthorized)
	}

	// Compare Hash Password
	if err := bcrypt.CompareHashAndPassword(
		[]byte(user.Password),
		[]byte(inputUser.Password),
	); err != nil {
		return c.SendStatus(fiber.StatusUnauthorized)
	}

	// Create JWT Token
	jwtSecretKey := os.Getenv("JWT_KEY")
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = user.UserID
	claims["email"] = user.Email
	claims["username"] = user.Username
	claims["full_name"] = user.FullName
	claims["role"] = user.Role
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	t, err := token.SignedString([]byte(jwtSecretKey))
	if err != nil {
		return c.SendStatus(fiber.StatusUnauthorized)
	}

	// Set Cookie
	c.Cookie(&fiber.Cookie{
		Name:     "jwt",
		Value:    t,
		Expires:  time.Now().Add(time.Hour * 24),
		HTTPOnly: true,
		SameSite: "None",
	})

	return c.JSON(fiber.Map{
		"message": "Login Successful",
	})
}

func listUser(db *gorm.DB, c *fiber.Ctx) error {
	var users []User

	// Get All User
	result := db.Find(&users)
	if result.Error != nil {
		log.Println("Error Get user:", result.Error)
		return c.Status(fiber.StatusNotFound).SendString("User not found")
	}

	return c.JSON(users)
}

func getUser(db *gorm.DB, c *fiber.Ctx) error {
	id := c.Params("id")

	// Get User By Id
	var user User
	result := db.First(&user, id)
	if result.Error != nil {
		log.Println("Error Get user:", result.Error)
		return c.Status(fiber.StatusNotFound).SendString("User not found")
	}

	return c.JSON(user)
}

func updateUser(db *gorm.DB, c *fiber.Ctx) error {
	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.SendStatus(fiber.StatusBadRequest)
	}

	var inputUser User
	if err := c.BodyParser(&inputUser); err != nil {
		return c.SendStatus(fiber.StatusBadRequest)
	}
	inputUser.UserID = uint(id)

	// Encrypt Password
	if inputUser.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword(
			[]byte(inputUser.Password),
			bcrypt.DefaultCost,
		)
		if err != nil {
			return err
		}
		inputUser.Password = string(hashedPassword)
	}

	// Update User
	result := db.Model(&inputUser).Updates(inputUser)
	if result.Error != nil {
		log.Println("Error Get user:", result.Error)
		return c.Status(fiber.StatusNotFound).SendString("User not found")
	}

	return c.JSON(fiber.Map{
		"message": "Update Successful",
	})
}

func deleteUser(db *gorm.DB, c *fiber.Ctx) error {
	id := c.Params("id")
	var user User

	// Delete User
	result := db.Delete(&user, id)
	if result.Error != nil {
		log.Println("Error Get user:", result.Error)
		return c.Status(fiber.StatusNotFound).SendString("User not found")
	}

	return c.JSON(fiber.Map{
		"message": "Delete Successful",
	})
}
