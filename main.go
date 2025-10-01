package main

import (
	"database/sql"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gorilla/sessions"
	"github.com/labstack/echo-contrib/session"
	"github.com/labstack/echo/v4"
	_ "github.com/lib/pq"
	"golang.org/x/crypto/bcrypt"
)

var db *sql.DB

// --------------------- Template Renderer ---------------------
type TemplateRenderer struct {
	templates *template.Template
}

func (t *TemplateRenderer) Render(w io.Writer, name string, data interface{}, c echo.Context) error {
	if data == nil {
		data = map[string]interface{}{}
	}
	return t.templates.ExecuteTemplate(w, name, data)
}

// --------------------- Structs ---------------------
type User struct {
	UserID        int
	UserCode      string
	Name          string
	Email         string
	Password      []byte
	Role          string
	Status        string
	InstitutionID int
	CreatedAt     time.Time
}

type Institution struct {
	ID   int64
	Name string
}

type Trade struct {
	ApprovedTradeID int64
	OrderID         int64
	InstrumentID    int64
	Side            string
	Quantity        float64
	Price           float64
	OrderCode       string
	Status          string
	OrderPlacer     int64
	PlacerName      string
	CounterpartName sql.NullString
}

type Security struct {
	InstrumentID int64
	Ticker       string
	Type         string
	Name         string
	MaturityDate time.Time
	FaceValue    float64
	CuponRate    sql.NullFloat64
	FixedRate    sql.NullFloat64
	Rating       string
}

type Order struct {
	OrderID        int64
	InstrumentID   int64
	InstrumentName string
	Side           string
	Quantity       float64
	Price          float64
	OrderCode      string
	Status         string
	Counterpart    string
}

type ApprovedTrade struct {
	ID          int
	OrderID     int
	Instrument  int64
	Side        string
	Quantity    float64
	Price       float64
	SecretCode  sql.NullString
	Status      string
	OrderPlacer int64  // the ID
	PlacerName  string // the name of the order placer
	ApprovedAt  time.Time
}

// --------------------- Helper ---------------------
func renderWithUser(c echo.Context, code int, name string, data map[string]interface{}) error {
	if data == nil {
		data = make(map[string]interface{})
	}
	sess, _ := session.Get("session", c)
	data["UserCode"] = sess.Values["user_code"]
	data["Name"] = sess.Values["user_name"]
	data["InstitutionID"] = sess.Values["institution_id"]
	data["InstitutionName"] = sess.Values["institution_name"]
	return c.Render(code, name, data)
}

// --------------------- Main ---------------------
func main() {
	var err error

	// Database connection
	connStr := os.Getenv("DATABASE_URL")
	if connStr == "" {
		connStr = "postgres://cleara_user:Mayhem@666@localhost:5432/cleara?sslmode=disable"
	}

	db, err = sql.Open("postgres", connStr)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	if err := db.Ping(); err != nil {
		panic(err)
	}

	// Echo setup
	e := echo.New()
	e.Use(session.Middleware(sessions.NewCookieStore([]byte("super-secret-key"))))

	// Load templates
	renderer := &TemplateRenderer{
		templates: template.Must(template.ParseGlob("templates/*.html")),
	}
	e.Renderer = renderer

	// Routes
	e.GET("/register", showRegister)
	e.POST("/register", registerUser)
	e.GET("/register-institution", showRegisterInstitution)
	e.POST("/register-institution", registerInstitution)
	e.GET("/register-account", showRegisterAccount)
	e.POST("/register-account", registerAccount)
	e.GET("/login", showLogin)
	e.POST("/login", loginUser)
	e.GET("/home", homePage)
	e.GET("/logout", logoutUser)
	e.GET("/register-fixed-income", showRegisterFixedIncome)
	e.POST("/register-fixed-income", handleRegisterFixedIncome)
	e.GET("/display-securities", showSecurities)
	e.POST("/order", handleTrade)
	e.POST("/approve-order", approveOrder)
	e.GET("/matching", showMatchingScreen)

	// Run matching engine in a goroutine
	go runMatchingEngine()

	e.Logger.Fatal(e.Start(":8080"))
}

// --------------------- Register ---------------------
func showRegister(c echo.Context) error {
	return c.Render(http.StatusOK, "register.html", nil)
}

func registerUser(c echo.Context) error {
	userCode := c.FormValue("user_code")
	name := c.FormValue("name")
	email := c.FormValue("email")
	password := c.FormValue("password")
	institutionID := c.FormValue("institution_id")
	role := "user"
	status := "active"

	hashed, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}

	_, err = db.Exec(`
	    INSERT INTO users (user_code, name, email, password_hash, role, status, institution_id, created_at)
	    VALUES ($1,$2,$3,$4,$5,$6,$7,NOW())`,
		userCode, name, email, hashed, role, status, institutionID)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}

	return c.Redirect(http.StatusSeeOther, "/login")
}

// --------------------- Login ---------------------
func showLogin(c echo.Context) error {
	return c.Render(http.StatusOK, "login.html", nil)
}

func loginUser(c echo.Context) error {
	email := c.FormValue("email")
	password := c.FormValue("password")

	var user User
	err := db.QueryRow(`
		SELECT user_id, user_code, name, email, password_hash, role, status, institution_id, created_at
		FROM users WHERE email=$1`, email).
		Scan(&user.UserID, &user.UserCode, &user.Name, &user.Email,
			&user.Password, &user.Role, &user.Status, &user.InstitutionID, &user.CreatedAt)
	if err != nil {
		if err == sql.ErrNoRows {
			return c.String(http.StatusUnauthorized, "Invalid credentials")
		}
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}

	if bcrypt.CompareHashAndPassword(user.Password, []byte(password)) != nil {
		return c.String(http.StatusUnauthorized, "Invalid credentials")
	}

	sess, _ := session.Get("session", c)
	sess.Values["user_id"] = user.UserID
	sess.Values["user_name"] = user.Name
	sess.Values["user_email"] = user.Email
	sess.Values["user_code"] = user.UserCode
	sess.Values["role"] = user.Role
	sess.Values["institution_id"] = user.InstitutionID
	sess.Save(c.Request(), c.Response())

	return c.Redirect(http.StatusSeeOther, "/home")
}

// --------------------- Logout ---------------------
func logoutUser(c echo.Context) error {
	sess, _ := session.Get("session", c)
	sess.Options.MaxAge = -1
	sess.Save(c.Request(), c.Response())
	return c.Redirect(http.StatusSeeOther, "/login")
}

// --------------------- Institutions ---------------------
func showRegisterInstitution(c echo.Context) error {
	sess, _ := session.Get("session", c)
	if sess.Values["user_id"] == nil {
		return c.Redirect(http.StatusSeeOther, "/login")
	}
	return c.Render(http.StatusOK, "register_institution.html", nil)
}

func homePage(c echo.Context) error {
	sess, _ := session.Get("session", c)
	instIDVal := sess.Values["institution_id"]
	if instIDVal == nil {
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	var instID int64
	switch v := instIDVal.(type) {
	case int:
		instID = int64(v)
	case int64:
		instID = v
	default:
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	rows, err := db.Query(`
        SELECT 
            o.order_id,
            o.instrument_id,
            ins.name AS instrument_name,
            o.side,
            o.quantity::text,
            o.price::text,
            o.order_code,
            o.status,
            COALESCE(i.name,'') AS counterpart_name
        FROM orders o
        LEFT JOIN instruments ins ON o.instrument_id = ins.instrument_id
        LEFT JOIN institutions i ON o.counterparty_id = i.institution_id
        WHERE o.institution_id=$1
        ORDER BY o.created_at DESC
    `, instID)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Query error: "+err.Error())
	}
	defer rows.Close()

	var pendingOrders, approvedOrders, rejectedOrders []Order

	for rows.Next() {
		var o Order
		var qtyStr, priceStr string
		var cp sql.NullString

		if err := rows.Scan(
			&o.OrderID,
			&o.InstrumentID,
			&o.InstrumentName,
			&o.Side,
			&qtyStr,
			&priceStr,
			&o.OrderCode,
			&o.Status,
			&cp,
		); err != nil {
			return c.String(http.StatusInternalServerError, "Scan error: "+err.Error())
		}

		if qtyStr != "" {
			if f, err := strconv.ParseFloat(qtyStr, 64); err == nil {
				o.Quantity = f
			}
		}
		if priceStr != "" {
			if f, err := strconv.ParseFloat(priceStr, 64); err == nil {
				o.Price = f
			}
		}

		if cp.Valid {
			o.Counterpart = cp.String
		}

		switch o.Status {
		case "pending":
			pendingOrders = append(pendingOrders, o)
		case "approved":
			approvedOrders = append(approvedOrders, o)
		case "rejected":
			rejectedOrders = append(rejectedOrders, o)
		}
	}

	return renderWithUser(c, http.StatusOK, "home.html", map[string]interface{}{
		"PendingOrders":  pendingOrders,
		"ApprovedOrders": approvedOrders,
		"RejectedOrders": rejectedOrders,
	})
}

func registerInstitution(c echo.Context) error {
	name := c.FormValue("name")
	instType := c.FormValue("type")
	country := c.FormValue("country")
	status := "active"

	if name == "" || instType == "" || country == "" {
		return c.String(http.StatusBadRequest, "Name, type, and country are required")
	}

	_, err := db.Exec(`INSERT INTO institutions (name,type,country,status,created_at) VALUES ($1,$2,$3,$4,NOW())`,
		name, instType, country, status)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}

	return c.Redirect(http.StatusSeeOther, "/home")
}

// --------------------- Accounts ---------------------
func showRegisterAccount(c echo.Context) error {
	sess, _ := session.Get("session", c)
	if sess.Values["user_id"] == nil {
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	rows, err := db.Query(`SELECT institution_id, name FROM institutions ORDER BY name`)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}
	defer rows.Close()

	var institutions []Institution
	for rows.Next() {
		var inst Institution
		if err := rows.Scan(&inst.ID, &inst.Name); err == nil {
			institutions = append(institutions, inst)
		}
	}

	return renderWithUser(c, http.StatusOK, "register_account.html", map[string]interface{}{
		"Institutions": institutions,
	})
}

func registerAccount(c echo.Context) error {
	institutionID := c.FormValue("institution_id")
	accountType := c.FormValue("account_type")
	currency := c.FormValue("currency")
	accountNumber := c.FormValue("account_number")

	_, err := db.Exec(`INSERT INTO accounts (institution_id, account_type, account_number, currency) VALUES ($1,$2,$3,$4)`,
		institutionID, accountType, accountNumber, currency)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Internal Server Error")
	}

	return c.Redirect(http.StatusSeeOther, "/home")
}

// --------------------- Fixed Income ---------------------
func showRegisterFixedIncome(c echo.Context) error {
	sess, _ := session.Get("session", c)
	if sess.Values["user_id"] == nil {
		return c.Redirect(http.StatusSeeOther, "/login")
	}
	return c.Render(http.StatusOK, "register_security.html", nil)
}

func handleRegisterFixedIncome(c echo.Context) error {
	sess, _ := session.Get("session", c)
	instID, ok := sess.Values["institution_id"].(int)
	if !ok {
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	ticker := c.FormValue("ticker")
	name := c.FormValue("name")
	instrumentType := c.FormValue("type")
	currency := c.FormValue("currency")
	issuer := c.FormValue("issuer")
	label := c.FormValue("label")
	status := c.FormValue("status")

	maturityDate, err := time.Parse("2006-01-02", c.FormValue("maturity_date"))
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid maturity date")
	}
	issueDate, err := time.Parse("2006-01-02", c.FormValue("issue_date"))
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid issue date")
	}

	faceValue, err := strconv.ParseFloat(c.FormValue("face_value"), 64)
	if err != nil {
		return c.String(http.StatusBadRequest, "Invalid face value")
	}

	var cuponRate, referencePercentage, fixedRate sql.NullFloat64
	if v := c.FormValue("cupon_rate"); v != "" {
		if val, err := strconv.ParseFloat(v, 64); err == nil {
			cuponRate = sql.NullFloat64{Float64: val, Valid: true}
		}
	}
	if v := c.FormValue("reference_percentage"); v != "" {
		if val, err := strconv.ParseFloat(v, 64); err == nil {
			referencePercentage = sql.NullFloat64{Float64: val, Valid: true}
		}
	}
	if v := c.FormValue("fixed_rate"); v != "" {
		if val, err := strconv.ParseFloat(v, 64); err == nil {
			fixedRate = sql.NullFloat64{Float64: val, Valid: true}
		}
	}

	tx, err := db.Begin()
	if err != nil {
		return c.String(http.StatusInternalServerError, "Database error")
	}
	defer tx.Rollback()

	var instrumentID int
	err = tx.QueryRow(`
        INSERT INTO instruments (ticker,name,type,currency,issuer,label,status,created_at)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8) RETURNING instrument_id`,
		ticker, name, instrumentType, currency, issuer, label, status, time.Now()).Scan(&instrumentID)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error inserting instrument: "+err.Error())
	}

	_, err = tx.Exec(`
        INSERT INTO fixed_income
        (instrument_id,maturity_date,cupon_rate,issue_date,face_value,frequency,
        day_count_convention,rating,reference_index,reference_percentage,rate_type,fixed_rate,institution_id)
        VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13)`,
		instrumentID, maturityDate, cuponRate, issueDate, faceValue,
		c.FormValue("frequency"), c.FormValue("day_count_convention"), c.FormValue("rating"),
		c.FormValue("reference_index"), referencePercentage, c.FormValue("rate_type"), fixedRate, instID)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error inserting fixed income: "+err.Error())
	}

	if err := tx.Commit(); err != nil {
		return c.String(http.StatusInternalServerError, "Transaction commit failed")
	}

	return c.Redirect(http.StatusSeeOther, "/register-fixed-income")
}

// --------------------- Securities ---------------------
func showSecurities(c echo.Context) error {
	sess, _ := session.Get("session", c)
	if sess.Values["user_id"] == nil {
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	rows, err := db.Query(`
		SELECT i.instrument_id, i.ticker, i.type, i.name, f.maturity_date, f.face_value, f.cupon_rate, f.fixed_rate, f.rating
		FROM instruments i
		JOIN fixed_income f ON i.instrument_id = f.instrument_id
		WHERE f.institution_id=$1
	`, sess.Values["institution_id"])
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error fetching securities")
	}
	defer rows.Close()

	var securities []Security
	for rows.Next() {
		var s Security
		if err := rows.Scan(&s.InstrumentID, &s.Ticker, &s.Type, &s.Name, &s.MaturityDate,
			&s.FaceValue, &s.CuponRate, &s.FixedRate, &s.Rating); err == nil {
			securities = append(securities, s)
		}
	}

	instRows, err := db.Query(`SELECT institution_id, name FROM institutions ORDER BY name`)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error fetching institutions")
	}
	defer instRows.Close()

	var institutions []Institution
	for instRows.Next() {
		var inst Institution
		if err := instRows.Scan(&inst.ID, &inst.Name); err == nil {
			institutions = append(institutions, inst)
		}
	}

	return renderWithUser(c, http.StatusOK, "securities.html", map[string]interface{}{
		"Securities":   securities,
		"Institutions": institutions,
	})
}

func handleTrade(c echo.Context) error {
	sess, _ := session.Get("session", c)
	userIDVal := sess.Values["user_id"]
	if userIDVal == nil {
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	instIDVal := sess.Values["institution_id"]
	var instID int64
	switch v := instIDVal.(type) {
	case int:
		instID = int64(v)
	case int64:
		instID = v
	default:
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	instrumentID, _ := strconv.ParseInt(c.FormValue("instrument_id"), 10, 64)
	counterpartyID, _ := strconv.ParseInt(c.FormValue("counterparty"), 10, 64)
	accountID, _ := strconv.ParseInt(c.FormValue("account_id"), 10, 64)
	side := c.FormValue("side")
	price, _ := strconv.ParseFloat(c.FormValue("price"), 64)
	quantity, _ := strconv.ParseFloat(c.FormValue("quantity"), 64)
	orderCode := c.FormValue("order_code")
	orderPlacer := userIDVal

	_, err := db.Exec(`
		INSERT INTO orders (instrument_id, institution_id, counterparty_id, account_id, side, quantity, price, order_placer, order_code, status, created_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8, $9,'pending',NOW())`,
		instrumentID, instID, counterpartyID, accountID, side, quantity, price, orderPlacer, orderCode)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error inserting order")
	}

	return c.Redirect(http.StatusSeeOther, "/home")
}

// --------------------- Approve Order ---------------------
func approveOrder(c echo.Context) error {
	var body struct {
		OrderID int64  `json:"order_id"`
		Status  string `json:"status"`
	}

	if err := c.Bind(&body); err != nil {
		return c.JSON(http.StatusBadRequest, map[string]string{"error": "invalid request body"})
	}

	_, err := db.Exec(`UPDATE orders SET status=$1 WHERE order_id=$2`, body.Status, body.OrderID)
	if err != nil {
		return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to update order"})
	}

	// Insert into approved_trades if approved
	if body.Status == "approved" {
		_, err = db.Exec(`
            INSERT INTO approved_trades (order_id, instrument_id, side, quantity, price, secret_code, status, order_placer, approved_at)
            SELECT order_id, instrument_id, side, quantity, price, order_code, 'pending_match', order_placer, NOW()
            FROM orders WHERE order_id=$1
        `, body.OrderID)
		if err != nil {
			return c.JSON(http.StatusInternalServerError, map[string]string{"error": "failed to insert into approved_trades"})
		}
	}

	return c.JSON(http.StatusOK, map[string]bool{"success": true})
}

// --------------------- Matching Engine ---------------------
func runMatchingEngine() {
	ticker := time.NewTicker(10 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		matchTrades()
	}
}

func matchTrades() {
	rows, err := db.Query(`
		SELECT approved_trade_id, order_id, instrument_id, side, quantity, price, secret_code, status, approved_at
		FROM approved_trades
		WHERE status='pending_match'
		ORDER BY approved_at ASC
	`)
	if err != nil {
		fmt.Println("Error fetching approved_trades:", err)
		return
	}
	defer rows.Close()

	var trades []ApprovedTrade
	for rows.Next() {
		var t ApprovedTrade
		if err := rows.Scan(&t.ID, &t.OrderID, &t.Instrument, &t.Side, &t.Quantity, &t.Price, &t.SecretCode, &t.Status, &t.ApprovedAt); err == nil {
			trades = append(trades, t)
		}
	}

	for i := 0; i < len(trades); i++ {
		for j := i + 1; j < len(trades); j++ {
			t1 := trades[i]
			t2 := trades[j]
			if t1.Instrument == t2.Instrument &&
				t1.Side != t2.Side &&
				t1.Quantity == t2.Quantity &&
				t1.Price == t2.Price &&
				t1.SecretCode.Valid && t2.SecretCode.Valid &&
				t1.SecretCode.String == t2.SecretCode.String {

				// Mark as matched
				db.Exec(`UPDATE approved_trades SET status='matched' WHERE id IN ($1,$2)`, t1.ID, t2.ID)
				fmt.Printf("Matched trades: %d and %d\n", t1.ID, t2.ID)
			}
		}
	}

}

// --------------------- Handler ---------------------
func showMatchingScreen(c echo.Context) error {
	sess, _ := session.Get("session", c)
	instIDVal := sess.Values["institution_id"]
	if instIDVal == nil {
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	var institutionID int64
	switch v := instIDVal.(type) {
	case int:
		institutionID = int64(v)
	case int64:
		institutionID = v
	default:
		return c.Redirect(http.StatusSeeOther, "/login")
	}

	rows, err := db.Query(`
         SELECT 
        at.approved_trade_id,
        at.order_id,
        at.instrument_id,
        at.side,
        at.quantity,
        at.price,
        at.secret_code AS order_code,
        at.status,
        at.order_placer,
        u.name AS placer_name,
        i.name AS counterpart_name
    FROM approved_trades at
    JOIN users u ON at.order_placer = u.user_id
    LEFT JOIN orders o ON at.order_id = o.order_id
    LEFT JOIN institutions i ON o.counterparty_id = i.institution_id
    WHERE (u.institution_id = $1 OR o.counterparty_id = $1)
      AND at.status = 'pending_match'
    ORDER BY at.approved_at DESC
    `, institutionID)
	if err != nil {
		return c.String(http.StatusInternalServerError, "Error fetching approved_trades: "+err.Error())
	}
	defer rows.Close()

	var trades []Trade
	for rows.Next() {
		var t Trade
		if err := rows.Scan(
			&t.ApprovedTradeID,
			&t.OrderID,
			&t.InstrumentID,
			&t.Side,
			&t.Quantity,
			&t.Price,
			&t.OrderCode,
			&t.Status,
			&t.OrderPlacer,
			&t.PlacerName,
			&t.CounterpartName,
		); err != nil {
			return c.String(http.StatusInternalServerError, "Error scanning row: "+err.Error())
		}
		trades = append(trades, t)
	}

	return renderWithUser(c, http.StatusOK, "matching.html", map[string]interface{}{
		"ApprovedTrades": trades,
	})
}
