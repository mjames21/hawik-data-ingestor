package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"

	elasticsearch "github.com/elastic/go-elasticsearch/v8"
	"github.com/elastic/go-elasticsearch/v8/esapi"
	"github.com/gofiber/fiber/v2"
	"github.com/gofiber/fiber/v2/middleware/cors"
	"github.com/joho/godotenv"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
)

var hc = &http.Client{Timeout: 15 * time.Second}

// GraduationCriteria maps your Excel/KoBo columns (flat).
type GraduationCriteria struct {
	Name             string `json:"name" bson:"name,omitempty"`
	Start            string `json:"start" bson:"start,omitempty"`
	End              string `json:"end" bson:"end,omitempty"`
	Today            string `json:"today" bson:"today,omitempty"`
	DeviceID         string `json:"deviceid" bson:"deviceid,omitempty"`
	IMEI             string `json:"imei" bson:"imei,omitempty"`
	PhoneNumber      string `json:"phonenumber" bson:"phonenumber,omitempty"`
	CoverPage        string `json:"cover_page" bson:"cover_page,omitempty"`
	Position         string `json:"position" bson:"position,omitempty"`
	A                string `json:"A" bson:"A,omitempty"`
	GPS              string `json:"gps" bson:"gps,omitempty"`
	StaffCode        string `json:"staff_code" bson:"staff_code,omitempty"`
	StaffCodePull    string `json:"staff_code_pull" bson:"staff_code_pull,omitempty"`
	StaffNamePull    string `json:"staff_name_pull" bson:"staff_name_pull,omitempty"`
	StaffConfirm     string `json:"staff_confirm" bson:"staff_confirm,omitempty"`
	TeamCal          string `json:"team_cal" bson:"team_cal,omitempty"`
	StaffFNameOther  string `json:"staff_fname_other" bson:"staff_fname_other,omitempty"`
	StaffLNameOther  string `json:"staff_lname_other" bson:"staff_lname_other,omitempty"`
	StaffName        string `json:"staff_name" bson:"staff_name,omitempty"`
	ErrorMessage1    string `json:"error_message1" bson:"error_message1,omitempty"`
	ConsentNote      string `json:"consent_note" bson:"consent_note,omitempty"`
	GeoSection       string `json:"geo_section" bson:"geo_section,omitempty"`
	HouseholdIDInput string `json:"household_id_input" bson:"household_id_input,omitempty"`
	HouseholdID      string `json:"household_id" bson:"household_id,omitempty"`
	NoPreloadNote    string `json:"nopreloadnote" bson:"nopreloadnote,omitempty"`

	GeoDetails       string `json:"geo_details" bson:"geo_details,omitempty"`
	District         string `json:"district" bson:"district,omitempty"`
	Chiefdom         string `json:"chiefdom" bson:"chiefdom,omitempty"`
	EaCode           string `json:"ea_code" bson:"ea_code,omitempty"`
	Section          string `json:"section" bson:"section,omitempty"`
	LocalityName     string `json:"locality_name" bson:"locality_name,omitempty"`
	ShowDistrict     string `json:"show_district" bson:"show_district,omitempty"`
	ShowChiefdom     string `json:"show_chiefdom" bson:"show_chiefdom,omitempty"`
	ShowEaCode       string `json:"show_ea_code" bson:"show_ea_code,omitempty"`
	ShowSection      string `json:"show_section" bson:"show_section,omitempty"`
	ShowLocalityName string `json:"show_locality_name" bson:"show_locality_name,omitempty"`

	MemberSection    string `json:"member_section" bson:"member_section,omitempty"`
	HohMemberIDInput string `json:"hoh_member_id_input" bson:"hoh_member_id_input,omitempty"`
	HohMemberID      string `json:"hoh_member_id" bson:"hoh_member_id,omitempty"`
	NoPreloadNote001 string `json:"nopreloadnote_001" bson:"nopreloadnote_001,omitempty"`

	Details                 string `json:"details" bson:"details,omitempty"`
	MemberName              string `json:"member_name" bson:"member_name,omitempty"`
	Gender                  string `json:"gender" bson:"gender,omitempty"`
	Age                     *int   `json:"age,string" bson:"age,omitempty"` // accept quoted numbers
	HouseholdMemberType     string `json:"household_member_type" bson:"household_member_type,omitempty"`
	HHHeadPhoto             string `json:"hh_head_photo" bson:"hh_head_photo,omitempty"`
	ShowMemberName          string `json:"show_member_name" bson:"show_member_name,omitempty"`
	ShowGender              string `json:"show_gender" bson:"show_gender,omitempty"`
	ShowAge                 string `json:"show_age" bson:"show_age,omitempty"`
	ShowHouseholdMemberType string `json:"show_household_member_type" bson:"show_household_member_type,omitempty"`

	InterviewSite      string `json:"interview_site" bson:"interview_site,omitempty"`
	InterviewSiteOther string `json:"interview_site_other" bson:"interview_site_other,omitempty"`
	IC                 string `json:"IC" bson:"IC,omitempty"`
	ICCP               string `json:"IC_CP" bson:"IC_CP,omitempty"`
	Intro              string `json:"intro" bson:"intro,omitempty"`
	InterviewDate      string `json:"interview_date" bson:"interview_date,omitempty"`
	HHSize             *int   `json:"hh_size,string" bson:"hh_size,omitempty"`

	FoodSecurity string `json:"food_security" bson:"food_security,omitempty"`
	Q1           string `json:"q1" bson:"q1,omitempty"`
	Q2           string `json:"q2" bson:"q2,omitempty"`

	Economic string `json:"economic" bson:"economic,omitempty"`
	Q3a      string `json:"q3a" bson:"q3a,omitempty"`
	Q3b      string `json:"q3b" bson:"q3b,omitempty"`
	Q3c      string `json:"q3c" bson:"q3c,omitempty"`
	Q3Score  *int   `json:"q3_score,string" bson:"q3_score,omitempty"`
	Q4       string `json:"q4" bson:"q4,omitempty"`

	BasicNeeds string `json:"basic_needs" bson:"basic_needs,omitempty"`
	Q5         string `json:"q5" bson:"q5,omitempty"`
	Q6a        string `json:"q6a" bson:"q6a,omitempty"`
	Q6b        string `json:"q6b" bson:"q6b,omitempty"`
	Q6c        string `json:"q6c" bson:"q6c,omitempty"`
	Q7         string `json:"q7" bson:"q7,omitempty"`
	Q8         string `json:"q8" bson:"q8,omitempty"`
	Q9         string `json:"q9" bson:"q9,omitempty"`

	Savings          string   `json:"savings" bson:"savings,omitempty"`
	Q10a             string   `json:"q10a" bson:"q10a,omitempty"`
	AssetSubgroup    string   `json:"asset_subgroup" bson:"asset_subgroup,omitempty"`
	Q10bI            string   `json:"q10b_i" bson:"q10b_i,omitempty"`
	Q10b             string   `json:"q10b" bson:"q10b,omitempty"`
	Q10bOther        string   `json:"q10b_other" bson:"q10b_other,omitempty"`
	AssetFirstClass  string   `json:"asset_first_class" bson:"asset_first_class,omitempty"`
	AssetFCName      string   `json:"asset_f_cname" bson:"asset_f_cname,omitempty"`
	ChoiceNumber     *int     `json:"choice_number,string" bson:"choice_number,omitempty"`
	Asset            string   `json:"asset" bson:"asset,omitempty"`
	AssetSecondClass string   `json:"asset_second_class" bson:"asset_second_class,omitempty"`
	AssetName        string   `json:"asset_name" bson:"asset_name,omitempty"`
	AssetNumber      *int     `json:"asset_number,string" bson:"asset_number,omitempty"`
	AssetValue       *float64 `json:"asset_value,string" bson:"asset_value,omitempty"`
	Q10Score         *int     `json:"q10_score,string" bson:"q10_score,omitempty"`

	Social   string `json:"social" bson:"social,omitempty"`
	Q11      string `json:"q11" bson:"q11,omitempty"`
	Q11Other string `json:"q11_other" bson:"q11_other,omitempty"`
	Q12      string `json:"q12" bson:"q12,omitempty"`
	Q11Score *int   `json:"q11_score,string" bson:"q11_score,omitempty"`

	SelfEfficacy string `json:"self_efficacy" bson:"self_efficacy,omitempty"`
	Q13a         string `json:"q13a" bson:"q13a,omitempty"`
	Q13b         string `json:"q13b" bson:"q13b,omitempty"`
	Q13c         string `json:"q13c" bson:"q13c,omitempty"`
	Q13d         string `json:"q13d" bson:"q13d,omitempty"`
	Q13Score     *int   `json:"q13_score,string" bson:"q13_score,omitempty"`

	GreenCount *int   `json:"green_count,string" bson:"green_count,omitempty"`
	HasRed     string `json:"has_red" bson:"has_red,omitempty"`
	GradStatus string `json:"grad_status" bson:"grad_status,omitempty"`
	Result     string `json:"result" bson:"result,omitempty"`
	Issues     string `json:"issues" bson:"issues,omitempty"`
	Problem    string `json:"problem" bson:"problem,omitempty"`
}

// --- Helpers ---
func getenv(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// parse optional "gps" string like "lat lon" or "lat,lon" into GeoJSON
func parseGPS(gps string) bson.M {
	gps = strings.TrimSpace(gps)
	if gps == "" {
		return nil
	}
	sep := " "
	if strings.Contains(gps, ",") {
		sep = ","
	}
	if strings.Contains(gps, ";") {
		sep = ";"
	}
	parts := strings.Split(gps, sep)
	if len(parts) != 2 {
		return nil
	}
	lat, err1 := strconv.ParseFloat(strings.TrimSpace(parts[0]), 64)
	lon, err2 := strconv.ParseFloat(strings.TrimSpace(parts[1]), 64)
	if err1 != nil || err2 != nil {
		return nil
	}
	return bson.M{"type": "Point", "coordinates": bson.A{lon, lat}} // [lon, lat]
}

// --- Mongo wiring ---
type mongoDeps struct {
	Client     *mongo.Client
	Collection *mongo.Collection
}

func connectMongo(ctx context.Context) (*mongoDeps, error) {
	uri := os.Getenv("MONGO_URI")
	dbName := getenv("MONGO_DB", "mis_app")
	collName := getenv("MONGO_COLLECTION", "graduation_criteria")

	if uri == "" {
		user := getenv("MONGO_USERNAME", "")
		pass := getenv("MONGO_PASSWORD", "")
		host := getenv("MONGO_HOST", "")
		opts := getenv("MONGO_OPTIONS", "tls=true&authSource=admin&replicaSet=db-mongodb-nacsa")
		if user == "" || pass == "" || host == "" || dbName == "" {
			return nil, fmt.Errorf("missing MONGO_* envs; set MONGO_URI or username/password/host/db")
		}
		h := strings.TrimPrefix(host, "mongodb+srv://")
		h = strings.TrimPrefix(h, "mongodb://")
		uri = fmt.Sprintf("mongodb+srv://%s:%s@%s/%s", url.QueryEscape(user), url.QueryEscape(pass), h, dbName)
		if opts != "" {
			uri += "?" + opts
		}
	}

	client, err := mongo.Connect(ctx, options.Client().ApplyURI(uri))
	if err != nil {
		return nil, err
	}
	if err := client.Ping(ctx, nil); err != nil {
		return nil, err
	}
	coll := client.Database(dbName).Collection(collName)
	_, _ = coll.Indexes().CreateOne(ctx, mongo.IndexModel{Keys: bson.D{{Key: "location", Value: "2dsphere"}}})
	return &mongoDeps{Client: client, Collection: coll}, nil
}

// --- Elasticsearch wiring (HTTPS + CA) ---
type esDeps struct{ Client *elasticsearch.Client }

func connectElasticsearchFromEnv() (*esDeps, error) {
	urls := getenv("ES_URLS", "")
	cloudID := getenv("ES_CLOUD_ID", "")
	apiKey := os.Getenv("ES_API_KEY")
	user := os.Getenv("ES_USERNAME")
	pass := os.Getenv("ES_PASSWORD")
	caPath := os.Getenv("ES_CA_CERT_PATH")
	verify := strings.ToLower(getenv("ES_VERIFY_SSL", "true")) != "false"

	// TLS config
	tlsCfg := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}
	if caPath != "" {
		pem, err := os.ReadFile(caPath)
		if err != nil {
			return nil, fmt.Errorf("read ES_CA_CERT_PATH: %w", err)
		}
		pool := x509.NewCertPool()
		if ok := pool.AppendCertsFromPEM(pem); !ok {
			return nil, fmt.Errorf("failed to append CA cert")
		}
		tlsCfg.RootCAs = pool
	}
	if !verify {
		// DEV ONLY
		tlsCfg.InsecureSkipVerify = true
	}

	transport := &http.Transport{
		TLSClientConfig:       tlsCfg,
		DialContext:           (&net.Dialer{Timeout: 5 * time.Second, KeepAlive: 30 * time.Second}).DialContext,
		ResponseHeaderTimeout: 10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
		IdleConnTimeout:       90 * time.Second,
		MaxIdleConns:          100,
		MaxIdleConnsPerHost:   10,
	}

	cfg := elasticsearch.Config{
		Transport:     transport,
		RetryOnStatus: []int{502, 503, 504},
		MaxRetries:    2,
	}

	if cloudID != "" {
		cfg.CloudID = cloudID
	}

	if urls != "" {
		cfg.Addresses = splitAndTrim(urls)
	} else if cloudID == "" {
		// Default to HTTPS since your node is TLS-enabled
		cfg.Addresses = []string{"https://localhost:9200"}
	}

	if apiKey != "" {
		cfg.APIKey = apiKey
	} else if user != "" || pass != "" {
		cfg.Username = user
		cfg.Password = pass
	}

	cli, err := elasticsearch.NewClient(cfg)
	if err != nil {
		return nil, err
	}

	// Strong startup check
	res, err := cli.Info()
	if err != nil {
		return nil, fmt.Errorf("es.Info: %w", err)
	}
	defer res.Body.Close()
	if res.IsError() {
		b, _ := io.ReadAll(res.Body)
		return nil, fmt.Errorf("es.Info status=%s body=%s", res.Status(), string(b))
	}

	return &esDeps{Client: cli}, nil
}

func esHealthHandler(es *esDeps) fiber.Handler {
	return func(c *fiber.Ctx) error {
		if es == nil || es.Client == nil {
			return c.Status(503).JSON(fiber.Map{"error": "elasticsearch not configured"})
		}
		res, err := es.Client.Info()
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "elasticsearch info failed", "detail": err.Error()})
		}
		defer res.Body.Close()
		var m map[string]any
		if err := json.NewDecoder(res.Body).Decode(&m); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "decode failed", "detail": err.Error()})
		}
		return c.JSON(m)
	}
}

func splitAndTrim(s string) []string {
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		if t := strings.TrimSpace(p); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// ---- Health & Stats ----

// /health → { mongo:{ok,db,collection}, elastic:{ok,name,cluster_name,version} }
func healthHandler(m *mongoDeps, es *esDeps) fiber.Handler {
	return func(c *fiber.Ctx) error {
		status := make(map[string]any)

		// Mongo
		mctx, cancel := context.WithTimeout(c.Context(), 3*time.Second)
		defer cancel()
		mongoInfo := map[string]any{
			"db":         m.Collection.Database().Name(),
			"collection": m.Collection.Name(),
		}
		if err := m.Client.Ping(mctx, nil); err != nil {
			mongoInfo["ok"] = false
			mongoInfo["error"] = err.Error()
		} else {
			mongoInfo["ok"] = true
		}
		status["mongo"] = mongoInfo

		// Elasticsearch
		if es == nil || es.Client == nil {
			status["elastic"] = map[string]any{"ok": false, "error": "not configured"}
		} else {
			res, err := es.Client.Info()
			if err != nil {
				status["elastic"] = map[string]any{"ok": false, "error": err.Error()}
			} else {
				defer res.Body.Close()
				var info map[string]any
				_ = json.NewDecoder(res.Body).Decode(&info)
				elk := map[string]any{"ok": true}
				if v, ok := info["name"]; ok {
					elk["name"] = v
				}
				if v, ok := info["cluster_name"]; ok {
					elk["cluster_name"] = v
				}
				if v, ok := info["version"]; ok {
					elk["version"] = v
				}
				status["elastic"] = elk
			}
		}

		code := http.StatusOK
		if v, _ := status["mongo"].(map[string]any); v != nil && v["ok"] == false {
			code = http.StatusServiceUnavailable
		}
		if v, _ := status["elastic"].(map[string]any); v != nil && v["ok"] == false {
			code = http.StatusServiceUnavailable
		}
		return c.Status(code).JSON(status)
	}
}

// /mongo/stats → dbStats + collStats + estimatedCount
func mongoStatsHandler(m *mongoDeps) fiber.Handler {
	return func(c *fiber.Ctx) error {
		ctx, cancel := context.WithTimeout(c.Context(), 5*time.Second)
		defer cancel()
		db := m.Collection.Database()

		var dbStats bson.M
		if err := db.RunCommand(ctx, bson.D{{Key: "dbStats", Value: 1}}).Decode(&dbStats); err != nil {
			dbStats = bson.M{"error": err.Error()}
		}

		var collStats bson.M
		if err := db.RunCommand(ctx, bson.D{{Key: "collStats", Value: m.Collection.Name()}}).Decode(&collStats); err != nil {
			collStats = bson.M{"error": err.Error()}
		}

		if count, err := m.Collection.EstimatedDocumentCount(ctx); err == nil {
			collStats["estimatedCount"] = count
		}

		return c.JSON(fiber.Map{
			"database":   db.Name(),
			"collection": m.Collection.Name(),
			"dbStats":    dbStats,
			"collStats":  collStats,
		})
	}
}

// --- HTTP Handlers ---
func handleNewSubmission(mDeps *mongoDeps, es *esDeps) fiber.Handler {
	return func(c *fiber.Ctx) error {
		var sub GraduationCriteria
		if err := c.BodyParser(&sub); err != nil {
			return c.Status(http.StatusBadRequest).JSON(fiber.Map{"error": "invalid JSON", "detail": err.Error()})
		}
		// Flatten: marshal struct -> bson.M, then attach computed fields
		raw, err := bson.Marshal(sub)
		if err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "marshal failed", "detail": err.Error()})
		}
		var doc bson.M
		if err := bson.Unmarshal(raw, &doc); err != nil {
			return c.Status(500).JSON(fiber.Map{"error": "unmarshal failed", "detail": err.Error()})
		}
		createdAt := time.Now().UTC()
		doc["created_at"] = createdAt
		if gp := parseGPS(sub.GPS); gp != nil {
			doc["location"] = gp
		}

		ctx, cancel := context.WithTimeout(c.Context(), 8*time.Second)
		defer cancel()
		if _, err := mDeps.Collection.InsertOne(ctx, doc); err != nil {
			return c.Status(http.StatusInternalServerError).JSON(fiber.Map{"error": "mongo insert failed", "detail": err.Error()})
		}

		// Optional: index into Elasticsearch if configured
		resp := fiber.Map{"message": "submission inserted"}
		if es != nil && es.Client != nil {
			indexName := getenv("ES_INDEX", "graduation_criteria")
			if indexName != "" {
				esDoc := make(map[string]any, len(doc)+1)
				for k, v := range doc {
					esDoc[k] = v
				}
				esDoc["@timestamp"] = createdAt
				body, _ := json.Marshal(esDoc)
				req := esapi.IndexRequest{Index: indexName, Body: bytes.NewReader(body), Refresh: "true"}
				res, err := req.Do(ctx, es.Client)
				if err != nil {
					resp["es_index_error"] = err.Error()
				} else {
					defer res.Body.Close()
					if res.IsError() {
						b, _ := io.ReadAll(res.Body)
						resp["es_index_error"] = fmt.Sprintf("status=%s body=%s", res.Status(), string(b))
					} else {
						resp["es_indexed"] = true
						resp["es_index"] = indexName
					}
				}
			}
		}
		return c.Status(http.StatusOK).JSON(resp)
	}
}

// --- main ---
func main() {
	_ = godotenv.Load()
	port := getenv("PORT", "8080")
	corsOrigin := getenv("CORS_ORIGIN", "*")

	app := fiber.New()
	app.Use(cors.New(cors.Config{
		AllowOrigins: corsOrigin,
		AllowHeaders: "Origin, Content-Type, Accept",
	}))

	rootCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Mongo
	deps, err := connectMongo(rootCtx)
	if err != nil {
		log.Fatalf("mongo connect: %v", err)
	}

	// Elasticsearch
	es, esErr := connectElasticsearchFromEnv()
	if esErr == nil {
		app.Get("/es/health", esHealthHandler(es))
	} else {
		log.Printf("Elasticsearch not configured/failed: %v", esErr)
		app.Get("/es/health", esHealthHandler(nil))
	}

	// Health & Stats
	app.Get("/health", healthHandler(deps, es))
	app.Get("/mongo/stats", mongoStatsHandler(deps))

	// Data ingest
	app.Post("/new_gc_submission", handleNewSubmission(deps, es))

	log.Printf("Server running on :%s", port)
	if err := app.Listen(":" + port); err != nil {
		log.Fatalf("Error starting server: %v", err)
	}
}
