package main

import (
	"log"
	"time"

	"net/http"

	"github.com/dgrijalva/jwt-go"
	"github.com/gin-gonic/gin"
	"gorm.io/driver/sqlserver"
	"gorm.io/gorm"
)

var db *gorm.DB
var err error

// Model User
type User struct {
	ID        uint   `json:"id"`
	Username  string `json:"username"`
	Email     string `json:"email"`
	Password  string `json:"password"`
	CreatedAt time.Time
	UpdatedAt time.Time
	Photos    []Photo `gorm:"foreignKey:UserID;constraint:OnUpdate:CASCADE,OnDelete:CASCADE;"`
}

// Model Photo
type Photo struct {
	ID        uint   `json:"id"`
	Title     string `json:"title"`
	Caption   string `json:"caption"`
	PhotoURL  string `json:"photoUrl"`
	UserID    uint   `json:"userId"`
	CreatedAt time.Time
	UpdatedAt time.Time
}

// JWT Claims structure
type Claims struct {
	Username string `json:"username"`
	jwt.StandardClaims
}

func main() {
	// Koneksi ke SQL Server
	dsn := "sqlserver://userdb:putraramawwalaqil@DESKTOP-2T5G4LS:63967?database=tugas5&connection+timeout=30&encrypt=disable"
	db, err = gorm.Open(sqlserver.Open(dsn), &gorm.Config{})
	if err != nil {
		log.Fatal(err)
	}

	// Migrasi Database
	db.AutoMigrate(&User{}, &Photo{})

	// Set up Gin router
	r := gin.Default()

	// Endpoint untuk registrasi user
	r.POST("/users/register", registerUser)

	// Endpoint untuk login user
	r.GET("/users/login", loginUser)

	// Middleware untuk validasi token JWT
	authMiddleware := jwtAuthMiddleware()

	// Endpoint untuk mengupdate user berdasarkan ID
	r.PUT("/users/:userId", authMiddleware, updateUser)

	// Endpoint untuk menghapus user berdasarkan ID
	r.DELETE("/users/:userId", authMiddleware, deleteUser)

	// Endpoint untuk menambahkan foto
	r.POST("/photos", authMiddleware, addPhoto)

	// Endpoint untuk mendapatkan semua foto
	r.GET("/photos", getPhotos)

	// Endpoint untuk mengupdate foto berdasarkan ID
	r.PUT("/photos/:photoId", authMiddleware, updatePhoto)

	// Endpoint untuk menghapus foto berdasarkan ID
	r.DELETE("/photos/:photoId", authMiddleware, deletePhoto)

	// Jalankan server
	err := r.Run(":8080")
	if err != nil {
		log.Fatal(err)
	}
}

// Handler untuk registrasi user
func registerUser(c *gin.Context) {
	var user User
	if err := c.ShouldBindJSON(&user); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validasi apakah atribut yang diperlukan ada
	if user.ID == 0 || user.Username == "" || user.Email == "" || user.Password == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "ID, Username, Email, dan Password harus diisi"})
		return
	}

	// Validasi panjang minimal password
	if len(user.Password) < 6 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Password harus memiliki panjang minimal 6 karakter"})
		return
	}

	// Simpan user ke database
	err := db.Create(&user).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan user ke database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Registrasi berhasil"})
}

// Handler untuk login user
func loginUser(c *gin.Context) {
	var userCredentials struct {
		Email    string `json:"email"`
		Password string `json:"password"`
	}

	if err := c.ShouldBindJSON(&userCredentials); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Cari user berdasarkan email
	var user User
	err := db.Where("email = ?", userCredentials.Email).First(&user).Error
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Email atau password salah"})
		return
	}

	// Dummy password verification
	if userCredentials.Password != user.Password {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Email atau password salah"})
		return
	}

	// Buat token JWT
	token, err := createJWTToken(user)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal membuat token JWT"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"token": token})
}

// Fungsi untuk membuat token JWT
func createJWTToken(user User) (string, error) {
	// Set up JWT claims
	claims := Claims{
		Username: user.Username,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Hour * 24).Unix(), // Token kadaluarsa dalam 1 hari
		},
	}

	// Membuat token dengan signing key dari environment variable
	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	tokenString, err := token.SignedString([]byte("secret-key"))

	if err != nil {
		return "", err
	}

	return tokenString, nil
}

// Middleware untuk otentikasi token JWT
func jwtAuthMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// Mendapatkan token dari header Authorization
		tokenString := c.GetHeader("Authorization")
		if tokenString == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token JWT tidak ditemukan"})
			c.Abort()
			return
		}

		// Memeriksa validitas token
		token, err := jwt.ParseWithClaims(tokenString, &Claims{}, func(token *jwt.Token) (interface{}, error) {
			return []byte("secret-key"), nil // Ganti dengan secret key yang sesuai
		})

		if err != nil || !token.Valid {
			c.JSON(http.StatusUnauthorized, gin.H{"error": "Token JWT tidak valid"})
			c.Abort()
			return
		}

		// Mengambil klaim dari token
		claims, ok := token.Claims.(*Claims)
		if !ok {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mendapatkan klaim token"})
			c.Abort()
			return
		}

		// Menyimpan informasi pengguna dari klaim ke konteks
		c.Set("user", claims.Username)

		c.Next()
	}
}

// Handler untuk mengupdate informasi pengguna berdasarkan ID
func updateUser(c *gin.Context) {
	userID := c.Param("userId")

	// Mendapatkan data pengguna dari database berdasarkan ID
	var user User
	err := db.First(&user, userID).Error
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Pengguna tidak ditemukan"})
		return
	}

	var updatedUser User
	if err := c.ShouldBindJSON(&updatedUser); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validasi data yang diperlukan
	if updatedUser.Username == "" || updatedUser.Email == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Username dan Email harus diisi"})
		return
	}

	// Update informasi pengguna di database
	user.Username = updatedUser.Username
	user.Email = updatedUser.Email

	// Simpan perubahan ke database
	err = db.Save(&user).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengupdate informasi pengguna"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Informasi pengguna berhasil diupdate"})
}

// Handler untuk menghapus user berdasarkan ID
func deleteUser(c *gin.Context) {
	// Mendapatkan ID dari parameter URL
	userID := c.Param("userId")

	var user User
	err := db.First(&user, userID).Error
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "User tidak ditemukan"})
		return
	}

	// Implementasikan logika delete user disini
	err = db.Delete(&user).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus user"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "User berhasil dihapus"})
}

// Handler untuk menambahkan foto
func addPhoto(c *gin.Context) {
	var photo Photo
	if err := c.ShouldBindJSON(&photo); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validasi apakah atribut yang diperlukan ada
	if photo.Title == "" || photo.Caption == "" || photo.PhotoURL == "" || photo.UserID == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Title, Caption, PhotoURL, dan UserID harus diisi"})
		return
	}

	// Simpan foto ke database
	err := db.Create(&photo).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menyimpan foto ke database"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Foto berhasil ditambahkan"})
}

// Handler untuk mendapatkan semua foto
func getPhotos(c *gin.Context) {
	var photos []Photo
	err := db.Find(&photos).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mendapatkan foto dari database"})
		return
	}

	c.JSON(http.StatusOK, photos)
}

// Handler untuk mengupdate foto berdasarkan ID
func updatePhoto(c *gin.Context) {
	// Mendapatkan ID dari parameter URL
	photoID := c.Param("photoId")

	var photo Photo
	err := db.First(&photo, photoID).Error
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Foto tidak ditemukan"})
		return
	}

	var updatedPhoto Photo
	if err := c.ShouldBindJSON(&updatedPhoto); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Validasi apakah atribut yang diperlukan ada
	if updatedPhoto.Title == "" || updatedPhoto.Caption == "" || updatedPhoto.PhotoURL == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Title, Caption, dan PhotoURL harus diisi"})
		return
	}

	// Update foto di database
	err = db.Model(&photo).Updates(&updatedPhoto).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal mengupdate foto"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Foto berhasil diupdate"})
}

// Handler untuk menghapus foto berdasarkan ID
func deletePhoto(c *gin.Context) {
	// Mendapatkan ID dari parameter URL
	photoID := c.Param("photoId")

	var photo Photo
	err := db.First(&photo, photoID).Error
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Foto tidak ditemukan"})
		return
	}

	// Implementasikan logika delete foto disini
	err = db.Delete(&photo).Error
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Gagal menghapus foto"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Foto berhasil dihapus"})
}
