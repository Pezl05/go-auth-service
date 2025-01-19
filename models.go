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

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
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

func logging(level, message string) {
	currentTime := time.Now().Format("2006-01-02 15:04:05")
	log.SetFlags(0)
	log.Printf("%s [%s] [Go Fiber] - %s", currentTime, level, message)
}

func createAdminUser(db *gorm.DB) {
	var admin User
	result := db.Where("role = ?", "admin").First(&admin)

	if result.Error != nil && result.Error == gorm.ErrRecordNotFound {
		fullName := "Admin User"
		admin = User{
			Username: "admin",
			Email:    "admin@example.com",
			Password: os.Getenv("ADMIN_PASSWORD"),
			FullName: &fullName,
			Role:     "admin",
		}

		hashedPassword, err := bcrypt.GenerateFromPassword(
			[]byte(admin.Password),
			bcrypt.DefaultCost,
		)
		if err != nil {
			logging("ERROR", "Error hashing password: "+err.Error())
			return
		}

		admin.Password = string(hashedPassword)
		result := db.Create(&admin)

		if result.Error != nil {
			logging("ERROR", "Error creating admin user: "+result.Error.Error())
		}

		logging("INFO", "Admin user created successfully: "+admin.Username)
	}
}

func register(db *gorm.DB, c *fiber.Ctx) error {
	tracer := otel.Tracer("register")
	cSpan, span := tracer.Start(c.Context(), "POST Register")
	defer span.End()

	var user User
	if err := c.BodyParser(&user); err != nil {
		span.RecordError(err)
		return c.SendStatus(fiber.StatusBadRequest)
	}

	span.SetAttributes(
		attribute.String("user.username", user.Username),
	)

	_, dbSpan := tracer.Start(cSpan, "dbQuery")
	defer dbSpan.End()

	var existingUser User
	if err := db.Where("username = ? OR email = ?", user.Username, user.Email).First(&existingUser).Error; err == nil {
		dbSpan.SetAttributes(
			attribute.String("message", "Username"+user.Username+"already exists"),
		)
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Username already exists",
		})
	}

	_, bcryptSpan := tracer.Start(cSpan, "bcryptCheck")
	defer bcryptSpan.End()

	hashedPassword, err := bcrypt.GenerateFromPassword(
		[]byte(user.Password),
		bcrypt.DefaultCost,
	)
	if err != nil {
		bcryptSpan.RecordError(err)
		logging("ERROR", "Error hashing password: "+err.Error())
		return err
	}

	_, registerSpan := tracer.Start(cSpan, "register")
	defer bcryptSpan.End()

	user.Password = string(hashedPassword)
	result := db.Create(&user)
	if result.Error != nil {
		registerSpan.RecordError(result.Error)
		logging("ERROR", "Failed to register user: "+result.Error.Error())
		return c.Status(fiber.StatusBadRequest).JSON(fiber.Map{
			"message": "Failed to register user",
		})
	}

	return c.JSON(fiber.Map{
		"message": "Register Successful",
	})
}

func login(db *gorm.DB, c *fiber.Ctx) error {
	tracer := otel.Tracer("login")
	cSpan, span := tracer.Start(c.Context(), "POST Login")
	defer span.End()

	var inputUser User
	var user User
	if err := c.BodyParser(&inputUser); err != nil {
		span.RecordError(err)
		return c.SendStatus(fiber.StatusBadRequest)
	}

	span.SetAttributes(
		attribute.String("user.username", inputUser.Username),
	)

	_, dbSpan := tracer.Start(cSpan, "dbQuery")
	defer dbSpan.End()

	result := db.Where(
		"username = ? OR email = ?",
		inputUser.Username, inputUser.Username,
	).First(&user)
	if result.Error != nil {
		dbSpan.RecordError(result.Error)
		return c.SendStatus(fiber.StatusUnauthorized)
	}

	_, bcryptSpan := tracer.Start(cSpan, "bcryptCheck")
	defer bcryptSpan.End()

	if err := bcrypt.CompareHashAndPassword(
		[]byte(user.Password),
		[]byte(inputUser.Password),
	); err != nil {
		bcryptSpan.RecordError(err)
		return c.SendStatus(fiber.StatusUnauthorized)
	}

	jwtSecretKey := os.Getenv("JWT_KEY")
	token := jwt.New(jwt.SigningMethodHS256)
	claims := token.Claims.(jwt.MapClaims)
	claims["user_id"] = user.UserID
	claims["email"] = user.Email
	claims["username"] = user.Username
	claims["full_name"] = user.FullName
	claims["role"] = user.Role
	claims["exp"] = time.Now().Add(time.Hour * 24).Unix()

	_, tokenSpan := tracer.Start(cSpan, "tokenSigned")
	defer tokenSpan.End()

	t, err := token.SignedString([]byte(jwtSecretKey))
	if err != nil {
		tokenSpan.RecordError(err)
		return c.SendStatus(fiber.StatusUnauthorized)
	}

	c.Cookie(&fiber.Cookie{
		Name:     "jwt",
		Value:    t,
		Expires:  time.Now().Add(time.Hour * 24),
		HTTPOnly: true,
		SameSite: "None",
	})

	logging("INFO", "Login successful for user: "+user.Username)
	return c.JSON(fiber.Map{
		"message": "Login Successful",
	})
}

func listUser(db *gorm.DB, c *fiber.Ctx) error {
	tracer := otel.Tracer("listUser")
	cSpan, span := tracer.Start(c.Context(), "GET Users")
	defer span.End()

	var users []User
	name := c.Query("name")
	role := c.Query("role")

	query := db.Model(&User{})
	if name != "" {
		query = query.Where("full_name ILIKE ?", "%"+name+"%")
		span.SetAttributes(
			attribute.String("username", name),
		)
	}
	if role != "" {
		query = query.Where("role = ?", role)
		span.SetAttributes(
			attribute.String("role", role),
		)
	}

	_, dbSpan := tracer.Start(cSpan, "dbQuery")
	defer dbSpan.End()

	result := query.Find(&users)
	if result.Error != nil {
		dbSpan.RecordError(result.Error)
		logging("ERROR", "Error getting users: "+result.Error.Error())
		return c.Status(fiber.StatusNotFound).SendString("User not found")
	}

	return c.JSON(users)
}

func getUser(db *gorm.DB, c *fiber.Ctx) error {
	tracer := otel.Tracer("getUser")
	cSpan, span := tracer.Start(c.Context(), "GET User")
	defer span.End()

	id := c.Params("id")

	span.SetAttributes(
		attribute.String("user.id", id),
	)

	_, dbSpan := tracer.Start(cSpan, "dbQuery")
	defer dbSpan.End()

	var user User
	result := db.First(&user, id)
	if result.Error != nil {
		dbSpan.RecordError(result.Error)
		return c.Status(fiber.StatusNotFound).SendString("User not found")
	}

	return c.JSON(user)
}

func updateUser(db *gorm.DB, c *fiber.Ctx) error {
	tracer := otel.Tracer("updateUser")
	cSpan, span := tracer.Start(c.Context(), "PATCH User")
	defer span.End()

	id, err := strconv.Atoi(c.Params("id"))
	if err != nil {
		return c.SendStatus(fiber.StatusBadRequest)
	}

	var inputUser User
	if err := c.BodyParser(&inputUser); err != nil {
		return c.SendStatus(fiber.StatusBadRequest)
	}
	inputUser.UserID = uint(id)

	span.SetAttributes(
		attribute.String("user.id", string(inputUser.UserID)),
	)

	_, bcryptSpan := tracer.Start(cSpan, "bcryptCheck")
	defer bcryptSpan.End()

	if inputUser.Password != "" {
		hashedPassword, err := bcrypt.GenerateFromPassword(
			[]byte(inputUser.Password),
			bcrypt.DefaultCost,
		)
		if err != nil {
			bcryptSpan.RecordError(err)
			logging("ERROR", "Error hashing password: "+err.Error())
			return err
		}
		inputUser.Password = string(hashedPassword)
	}

	_, dbSpan := tracer.Start(cSpan, "dbQuery")
	defer dbSpan.End()

	result := db.Model(&inputUser).Updates(inputUser)
	if result.Error != nil {
		dbSpan.RecordError(result.Error)
		return c.Status(fiber.StatusNotFound).SendString("User not found")
	}

	return c.JSON(fiber.Map{
		"message": "Update Successful",
	})
}

func deleteUser(db *gorm.DB, c *fiber.Ctx) error {
	tracer := otel.Tracer("deleteUser")
	cSpan, span := tracer.Start(c.Context(), "Delete User")
	defer span.End()

	id := c.Params("id")
	var user User

	span.SetAttributes(
		attribute.String("user.id", id),
	)

	_, dbSpan := tracer.Start(cSpan, "dbQuery")
	defer dbSpan.End()

	result := db.Delete(&user, id)
	if result.Error != nil {
		dbSpan.RecordError(result.Error)
		logging("ERROR", "Error deleting user by ID: "+id+" - "+result.Error.Error())
		return c.Status(fiber.StatusNotFound).SendString("User not found")
	}

	logging("INFO", "User deleted successfully: ID "+id)
	return c.JSON(fiber.Map{
		"message": "Delete Successful",
	})
}
