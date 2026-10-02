package postgres

import (
	"math"
	"math/big"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5/pgtype"
)

func workParameters(sql string, args []any) ([]any, error) {
	if len(sql) == 0 || len(sql) > 65536 || !utf8.ValidString(sql) || strings.IndexByte(sql, 0) >= 0 || len(args) > 64 {
		return nil, invalidWork()
	}
	text := strings.TrimLeft(sql, " \t\r\n")
	i := 0
	for i < len(text) && (text[i] >= 'a' && text[i] <= 'z' || text[i] >= 'A' && text[i] <= 'Z') {
		i++
	}
	switch strings.ToUpper(text[:i]) {
	case "SELECT", "INSERT", "UPDATE", "DELETE", "WITH":
	default:
		return nil, invalidWork()
	}
	result := make([]any, len(args))
	size := 0
	for i, value := range args {
		cost := 8
		switch v := value.(type) {
		case nil, bool, int, int16, int32, int64, uint32, uint64:
		case float64:
			if math.IsNaN(v) || math.IsInf(v, 0) {
				return nil, invalidWork()
			}
		case string:
			cost = len(v)
		case []byte:
			cost = len(v)
		case time.Time:
			if !postgresExactTime(v) {
				return nil, invalidWork()
			}
			value = v.UTC()
			cost = 16
		default:
			return nil, invalidWork()
		}
		if cost > 1<<20-size {
			return nil, invalidWork()
		}
		size += cost
		if b, ok := value.([]byte); ok {
			if b != nil {
				owned := make([]byte, len(b))
				copy(owned, b)
				value = owned
			}
		}
		result[i] = value
	}
	return result, nil
}

// Only our closed primitive values reach this fixed binary profile. No custom
// codec or marshaler supplied by a caller is invoked under the transaction.
func encodeWorkParameters(codecs *pgtype.Map, args []any) ([][]byte, []uint32, []int16, error) {
	values := make([][]byte, len(args))
	oids := make([]uint32, len(args))
	formats := make([]int16, len(args))
	for i, value := range args {
		if value == nil {
			continue
		}
		formats[i] = pgtype.BinaryFormatCode
		switch v := value.(type) {
		case bool:
			oids[i] = pgtype.BoolOID
		case int:
			oids[i] = pgtype.Int8OID
			value = int64(v)
		case int16:
			oids[i] = pgtype.Int2OID
		case int32:
			oids[i] = pgtype.Int4OID
		case int64:
			oids[i] = pgtype.Int8OID
		case uint32:
			oids[i] = pgtype.Int8OID
			value = int64(v)
		case uint64:
			oids[i] = pgtype.NumericOID
			value = pgtype.Numeric{Int: new(big.Int).SetUint64(v), Valid: true}
		case float64:
			oids[i] = pgtype.Float8OID
		case string:
			oids[i] = pgtype.TextOID
		case []byte:
			oids[i] = pgtype.ByteaOID
		case time.Time:
			oids[i] = pgtype.TimestamptzOID
		default:
			return nil, nil, nil, invalidWork()
		}
		// A nonnil empty buffer preserves empty byte/text values. Nil encoded
		// bytes mean SQL NULL in extended Bind, not a zero-length value.
		encoded, err := codecs.Encode(oids[i], formats[i], value, make([]byte, 0))
		if err != nil {
			return nil, nil, nil, invalidWork()
		}
		values[i] = encoded
	}
	return values, oids, formats, nil
}

func workDestinations(dest []any) bool {
	if len(dest) > 64 {
		return false
	}
	for _, d := range dest {
		switch p := d.(type) {
		case nil:
		case *bool:
			if p == nil {
				return false
			}
		case *int:
			if p == nil {
				return false
			}
		case *int16:
			if p == nil {
				return false
			}
		case *int32:
			if p == nil {
				return false
			}
		case *int64:
			if p == nil {
				return false
			}
		case *uint32:
			if p == nil {
				return false
			}
		case *uint64:
			if p == nil {
				return false
			}
		case *float64:
			if p == nil {
				return false
			}
		case *string:
			if p == nil {
				return false
			}
		case *[]byte:
			if p == nil {
				return false
			}
		case *time.Time:
			if p == nil {
				return false
			}
		case **string:
			if p == nil {
				return false
			}
		case **int64:
			if p == nil {
				return false
			}
		case **time.Time:
			if p == nil {
				return false
			}
		default:
			return false
		}
	}
	return true
}
