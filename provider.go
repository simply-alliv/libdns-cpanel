package cpanel

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/libdns/libdns"
)

// Provider facilitates DNS record manipulation via cPanel UAPI DNS module.
type Provider struct {
	Host     string `json:"host,omitempty"`
	Username string `json:"username,omitempty"`
	APIToken string `json:"api_token,omitempty"`
}

// parseZoneEntry models the result of DNS::parse_zone
type parseZoneEntry struct {
	LineIndex   int      `json:"line_index"`
	RecordType  string   `json:"record_type"`
	TTL         int      `json:"ttl"`
	DNameB64    string   `json:"dname_b64"`
	DataB64     []string `json:"data_b64"`
}

// dial sends a GET request to the cPanel UAPI.
func (p *Provider) dial(ctx context.Context, module, function string, params url.Values) (json.RawMessage, error) {
	reqURL := fmt.Sprintf("%s/execute/%s/%s?%s", strings.TrimRight(p.Host, "/"), module, function, params.Encode())
	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}
	req.SetBasicAuth(p.Username, p.APIToken)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	var envelope struct {
		Result struct {
			Status int             `json:"status"`
			Data   json.RawMessage `json:"data"`
		} `json:"result"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, err
	}
	if envelope.Result.Status != 1 {
		return nil, errors.New("API call failed")
	}
	return envelope.Result.Data, nil
}

// GetRecords lists all the records in the zone.
func (p *Provider) GetRecords(ctx context.Context, zone string) ([]libdns.Record, error) {
	params := url.Values{"zone": {zone}}
	raw, err := p.dial(ctx, "DNS", "parse_zone", params)
	if err != nil {
		return nil, err
	}

	var entries []parseZoneEntry
	if err := json.Unmarshal(raw, &entries); err != nil {
		return nil, err
	}

	var records []libdns.Record
	for _, e := range entries {
		nameBytes, _ := base64.StdEncoding.DecodeString(e.DNameB64)
		var dataParts []string
		for _, d := range e.DataB64 {
			bytes, _ := base64.StdEncoding.DecodeString(d)
			dataParts = append(dataParts, string(bytes))
		}
		records = append(records, libdns.Record{
			Type:  e.RecordType,
			Name:  strings.TrimSuffix(string(nameBytes), "."+zone),
			Value: strings.Join(dataParts, " "),
			TTL:   uint32(e.TTL),
			Metadata: map[string]string{
				"line_index": strconv.Itoa(e.LineIndex),
			},
		})
	}
	return records, nil
}

// AppendRecords adds records to the zone using mass_edit_zone.
func (p *Provider) AppendRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	// Fetch current serial
	existing, err := p.GetRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	serial := "0"
	for _, r := range existing {
		if r.Type == "SOA" {
			parts := strings.Fields(r.Value)
			if len(parts) >= 3 {
				serial = parts[2]
			}
			break
		}
	}

	var add []map[string]interface{}
	for _, r := range records {
		add = append(add, map[string]interface{}{
			"record_type": r.Type,
			"dname":       r.Name + "." + zone,
			"ttl":         r.TTL,
			"data":        []string{r.Value},
		})
	}

	addJson, _ := json.Marshal(add)
	params := url.Values{
		"zone":   {zone},
		"serial": {serial},
		"add":    {string(addJson)},
	}

	_, err = p.dial(ctx, "DNS", "mass_edit_zone", params)
	if err != nil {
		return nil, err
	}
	return records, nil
}

// DeleteRecords deletes records from the zone using mass_edit_zone.
func (p *Provider) DeleteRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	existing, err := p.GetRecords(ctx, zone)
	if err != nil {
		return nil, err
	}

	serial := "0"
	var toRemove []string
	for _, r := range records {
		for _, ex := range existing {
			if r.Type == ex.Type && r.Name == ex.Name && r.Value == ex.Value {
				toRemove = append(toRemove, ex.Metadata["line_index"])
				if ex.Type == "SOA" {
					parts := strings.Fields(ex.Value)
					if len(parts) >= 3 {
						serial = parts[2]
					}
				}
			}
		}
	}
	removeJson, _ := json.Marshal(toRemove)
	params := url.Values{
		"zone":   {zone},
		"serial": {serial},
		"remove": {string(removeJson)},
	}
	_, err = p.dial(ctx, "DNS", "mass_edit_zone", params)
	if err != nil {
		return nil, err
	}
	return records, nil
}

// SetRecords replaces records by deleting and then appending them.
func (p *Provider) SetRecords(ctx context.Context, zone string, records []libdns.Record) ([]libdns.Record, error) {
	_, err := p.DeleteRecords(ctx, zone, records)
	if err != nil {
		return nil, err
	}
	return p.AppendRecords(ctx, zone, records)
}

var (
	_ libdns.RecordGetter   = (*Provider)(nil)
	_ libdns.RecordAppender = (*Provider)(nil)
	_ libdns.RecordSetter   = (*Provider)(nil)
	_ libdns.RecordDeleter  = (*Provider)(nil)
)