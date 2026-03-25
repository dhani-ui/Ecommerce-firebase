package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"strings"

	firebase "firebase.google.com/go/v4"
	"firebase.google.com/go/v4/auth"
	_ "github.com/lib/pq"
	"google.golang.org/api/option"
)

var db *sql.DB
var authClient *auth.Client

type AppUser struct {
	ID          string `json:"id"`
	FirebaseUID string `json:"firebase_uid"`
	Email       string `json:"email"`
	Role        string `json:"role"`
}

type Product struct {
	ID       string  `json:"id"`
	Name     string  `json:"name"`
	Price    float64 `json:"price"`
	ImageURL string  `json:"image_url"`
}

func init() {
	var err error
	// SESUAIKAN PASSWORD DAN DBNAME DENGAN POSTGRESQL ANDA
	connStr := "user=postgres password=password_kamu dbname=ecommerce sslmode=disable"
	db, err = sql.Open("postgres", connStr)
	if err != nil {
		log.Fatal(err)
	}

	opt := option.WithCredentialsFile("serviceAccountKey.json")
	app, err := firebase.NewApp(context.Background(), nil, opt)
	if err != nil {
		log.Fatal("Gagal load Firebase:", err)
	}
	authClient, err = app.Auth(context.Background())
}

// --- MIDDLEWARE ---
func CORS(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Authorization, Content-Type")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	}
}

func AuthMiddleware(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if !strings.HasPrefix(authHeader, "Bearer ") {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		token, err := authClient.VerifyIDToken(r.Context(), strings.TrimPrefix(authHeader, "Bearer "))
		if err != nil {
			http.Error(w, "Invalid Token", http.StatusUnauthorized)
			return
		}

		// Sinkronisasi DB
		var user AppUser
		err = db.QueryRowContext(r.Context(), "SELECT id, firebase_uid, email, role FROM users WHERE firebase_uid = $1", token.UID).
			Scan(&user.ID, &user.FirebaseUID, &user.Email, &user.Role)
		
		if err == sql.ErrNoRows {
			email := token.Claims["email"].(string)
			db.QueryRowContext(r.Context(), "INSERT INTO users (firebase_uid, email, role) VALUES ($1, $2, 'customer') RETURNING id", token.UID, email).Scan(&user.ID)
			user.FirebaseUID, user.Email, user.Role = token.UID, email, "customer"
		}

		ctx := context.WithValue(r.Context(), "user", &user)
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// --- HANDLERS ---
func GetProducts(w http.ResponseWriter, r *http.Request) {
	rows, _ := db.Query("SELECT id, name, price, image_url FROM products")
	defer rows.Close()
	var products []Product
	for rows.Next() {
		var p Product
		rows.Scan(&p.ID, &p.Name, &p.Price, &p.ImageURL)
		products = append(products, p)
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(products)
}

func GetProfile(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(*AppUser)
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

func main() {
	http.HandleFunc("/api/products", CORS(GetProducts))
	http.HandleFunc("/api/profile", CORS(AuthMiddleware(GetProfile)))

	log.Println("Server Golang jalan di http://localhost:8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}
