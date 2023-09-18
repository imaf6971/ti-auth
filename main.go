package main

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/mail"
	"os"

	"github.com/go-chi/chi/v5"
	"github.com/google/uuid"
	"github.com/imaf6971/ti-auth/password"
	"github.com/imaf6971/ti-auth/types"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

var dbpool *pgxpool.Pool

func handleUserRegister(w http.ResponseWriter, r *http.Request) {
	var user types.User

	err := json.NewDecoder(r.Body).Decode(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	if !isValidEmail(user.Email) {
		http.Error(w, "Email is not valid", http.StatusBadRequest)
		return
	}
	err = registerUser(&user)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusCreated)
}

func registerUser(user *types.User) error {
	hashedPassword, err := password.GenerateHashFromPassword(user.Password, password.DefaultParams())
	if err != nil {
		return err
	}

	_, err = dbpool.Exec(
		context.Background(),
		"insert into users(email, passwordHash) values ($1, $2)",
		user.Email, hashedPassword,
	)

	if err != nil {
		return err
	}

	return nil
}

func isValidEmail(email string) bool {
	_, err := mail.ParseAddress(email)
	return err == nil
}

func handleUserLogin(w http.ResponseWriter, r *http.Request) {
	var userLogin types.User

	err := json.NewDecoder(r.Body).Decode(&userLogin)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if !isValidEmail(userLogin.Email) {
		http.Error(w, "Email is not valid", http.StatusBadRequest)
		return
	}

	dbUser, err := getUser(userLogin.Email)
	if err == pgx.ErrNoRows {
		http.Error(w, "Can't find user with this email", http.StatusNotFound)
		return
	}
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	isPasswordMatch, err := password.VerifyPassword(userLogin.Password, dbUser.Password)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	if !isPasswordMatch {
		http.Error(w, "Password doesn't match", http.StatusBadRequest)
		return
	}

	sidValue := uuid.New().String()
	http.SetCookie(w, &http.Cookie{
		Name:     "SID",
		Value:    sidValue,
		HttpOnly: true,
	})
}

func getUser(email string) (*types.User, error) {
	var user types.User

	row := dbpool.QueryRow(context.Background(), "select email, passwordhash from users where email = $1", email)
	err := row.Scan(&user.Email, &user.Password)
	if err != nil {
		return nil, err
	}
	return &user, nil
}

func handleUserLogout(w http.ResponseWriter, r *http.Request) {

}

func handleCreateApplication(w http.ResponseWriter, r *http.Request) {

}

func lookupEnv(key string, deefault string) string {
	envVar, isExists := os.LookupEnv(key)
	if !isExists {
		return deefault
	}

	return envVar
}

func main() {
	var err error = nil
	connString := lookupEnv("DB_CONNSTR", "postgres://postgres:imfa1796@localhost:5432/postgres")
	dbpool, err = pgxpool.New(context.Background(), connString)
	if err != nil {
		slog.Error("Unable to create connection pool: %v", err)
		os.Exit(1)
	}
	defer dbpool.Close()

	r := chi.NewRouter()

	r.Post("/api/v1/auth/register", handleUserRegister)
	r.Post("/api/v1/auth/login", handleUserLogin)
	r.Post("/api/v1/auth/logout", handleUserLogout)
	r.Post("/api/v1/applications", handleCreateApplication)

	listenAddr := lookupEnv("LISTENADDR", ":3000")
	fmt.Println(listenAddr)
	slog.Info("Starting server on addr", listenAddr)
	http.ListenAndServe(listenAddr, r)
}
