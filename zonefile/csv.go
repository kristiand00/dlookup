package zonefile

import (
	"encoding/csv"
	"fmt"
	"io"
	"strconv"
	"strings"
)

var csvHeader = []string{"name", "type", "ttl", "data", "proxied", "comment"}

func parseCSV(r io.Reader, origin string) (*Zone, error) {
	cr := csv.NewReader(r)
	cr.FieldsPerRecord = -1
	cr.Comment = '#'
	rows, err := cr.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(rows) == 0 {
		return nil, fmt.Errorf("empty file")
	}
	col := map[string]int{}
	for i, h := range rows[0] {
		col[strings.ToLower(strings.TrimSpace(strings.TrimPrefix(h, "\ufeff")))] = i
	}
	for _, need := range []string{"name", "type", "data"} {
		if _, ok := col[need]; !ok {
			return nil, fmt.Errorf("header must have the columns %s (missing %q)", strings.Join(csvHeader, ","), need)
		}
	}
	get := func(row []string, key string) string {
		if i, ok := col[key]; ok && i < len(row) {
			return strings.TrimSpace(row[i])
		}
		return ""
	}
	z := &Zone{Origin: origin}
	o := origin
	if o == "" {
		o = "."
	}
	for n, row := range rows[1:] {
		if len(row) == 1 && strings.TrimSpace(row[0]) == "" {
			continue
		}
		rec := Record{
			Name:    absName(get(row, "name"), o),
			Type:    strings.ToUpper(get(row, "type")),
			Data:    get(row, "data"),
			Comment: get(row, "comment"),
		}
		if rec.Type == "" {
			return nil, fmt.Errorf("line %d: empty type", n+2)
		}
		if t := get(row, "ttl"); t != "" {
			v, err := strconv.ParseUint(t, 10, 32)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid ttl %q", n+2, t)
			}
			rec.TTL = uint32(v)
		}
		if p := get(row, "proxied"); p != "" {
			b, err := strconv.ParseBool(p)
			if err != nil {
				return nil, fmt.Errorf("line %d: invalid proxied %q", n+2, p)
			}
			rec.Proxied = &b
		}
		z.Records = append(z.Records, rec)
	}
	return z, nil
}

func writeCSV(w io.Writer, z *Zone, wr *writer) error {
	cw := csv.NewWriter(w)
	if err := cw.Write(csvHeader); err != nil {
		return err
	}
	for _, r := range z.Records {
		ttl, proxied := "", ""
		if r.TTL > 0 {
			ttl = strconv.FormatUint(uint64(r.TTL), 10)
		}
		if r.Proxied != nil {
			proxied = strconv.FormatBool(*r.Proxied)
		}
		if err := cw.Write([]string{r.Name, r.Type, ttl, r.Data, proxied, r.Comment}); err != nil {
			return err
		}
	}
	cw.Flush()
	return cw.Error()
}
