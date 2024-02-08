package utils

import (
	"context"
	"github.com/d3mondev/resolvermt"
	tgbotapi "github.com/go-telegram-bot-api/telegram-bot-api"
	"github.com/projectdiscovery/dnsx/libs/dnsx"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"log"
	"time"
	"strings"
)

type Data struct {
	Subdomain string   `json:"subdomain"`
	Source    []string `json:"source"`
	IPs       []string `json:"ips"`
	Date      time.Time   `json:"date"`
}

type Request struct {
	Domain string `json:"domain"`
}

func CollList(client *mongo.Client, dbname string) []string {

	collectionNames, err := client.Database(dbname).ListCollectionNames(context.Background(), bson.D{})
	if err != nil {
		panic(err)
	}
	var domains []string
	for _, name := range collectionNames {
		domains = append(domains, name)
	}
	return domains
}

func DnsxResolver(Subdomain string) []string {
	// Create DNS Resolver with default options
	dnsClient, err := dnsx.New(dnsx.DefaultOptions)
	if err != nil {
		panic(err)
	}

	result, _ := dnsClient.Lookup(Subdomain)

	return result
}

func PureResolver(Domains []string, MaxConcurrency int) []string {
	resolvers := []string{
		"8.8.8.8",
		"8.8.4.4",
		"9.9.9.10",
		"1.1.1.1",
	}

	client := resolvermt.New(resolvers, 3, 100, MaxConcurrency)
	defer client.Close()

	results := client.Resolve(Domains, resolvermt.TypeA)

	var resolved []string

	for _, record := range results {
		if record.Answer != "" {
			resolved = append(resolved, record.Question)
		}
	}
	return resolved
}

func GetDomainsFromDB(client *mongo.Client) []string {
	query := bson.M{}
	cursur, err := client.Database("assets").Collection("domains").Find(context.Background(), query)
	if err != nil {
		panic(err)
	}

	defer cursur.Close(context.Background())

	var domains []string
	for cursur.Next(context.Background()) {
		var domain Request
		err = cursur.Decode(&domain)
		if err != nil {
			panic(err)
		}

		domains = append(domains, domain.Domain)
	}

	return domains
}

func GetSubsFromDB(client *mongo.Client, DbName, Domain string) []string {

	filter := bson.D{}

	// Get a handle to the collection
	cursur, err := client.Database(DbName).Collection(Domain).Find(context.Background(), filter)
	if err != nil {
		panic(err)
	}

	defer cursur.Close(context.Background())

	var AllSubs []string

	for cursur.Next(context.Background()) {
		var subs Data
		err = cursur.Decode(&subs)
		if err != nil {
			panic(err)
		}

		AllSubs = append(AllSubs, subs.Subdomain)
	}

	return AllSubs
}

func FormatList(items []string) string {
	if len(items) == 0 {
		return "N/A"
	}

	return strings.Join(items, " - ")
}

func SendTelegramData(Message, Token string, ChatID int64) error {
	// Create a new bot instance
	bot, err := tgbotapi.NewBotAPI(Token)
	if err != nil {
		log.Fatal(err)
	}

	// Create a message configuration
	msg := tgbotapi.NewMessage(ChatID, Message)
	msg.ParseMode = tgbotapi.ModeMarkdown

	// Send the message
	_, err = bot.Send(msg)
	return err
}

func ConnectToMongoDB(URI string) (*mongo.Client, error) {
	clientOptions := options.Client().ApplyURI(URI)
	return mongo.Connect(context.Background(), clientOptions)
}
