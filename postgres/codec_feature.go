package postgres

import identity "github.com/faustbrian/go-identity"

// Only prepareClaim supplies the validated immutable command projection. This
// shared mapping preserves all explicit scalar kinds without inventing schema
// authority. Domain adapters must still exhaustively map and validate their
// native typed commands before coordinator admission. No raw values are stored.
func encodeFeature(s identity.FeatureCommandSpec, key [32]byte) (map[string][]byte, error) {
	fields := make(map[string][]byte, len(s.Fields))
	for _, field := range s.Fields {
		value, err := encodeFeatureValue(field.Value)
		if err != nil {
			return nil, err
		}
		// The structural vocabulary carries no disclosure classification. Digest
		// every scalar conservatively, not only text/bytes, and bind the kind
		// separately so equal scalar encodings cannot alias distinct intent.
		digest, err := commandSecret(key, "feature."+field.Name, value, 8195)
		if err != nil {
			return nil, err
		}
		fields[field.Name] = cborMap(map[string][]byte{
			"kind": cborUint(uint64(field.Value.Kind)), "value": cborBytes(digest),
		})
	}
	result := map[string][]byte{
		"feature_owner":      cborText(s.Operation.Owner),
		"record_requirement": cborUint(uint64(s.Operation.RecordRequirement)),
		"fields":             cborMap(fields),
	}
	if s.Operation.SubjectRequirement != identity.FeatureSubjectUser {
		result["subject_requirement"] = cborUint(uint64(s.Operation.SubjectRequirement))
	}
	if s.Operation.VersionPolicy != identity.FeatureVersionSequential {
		result["version_policy"] = cborUint(uint64(s.Operation.VersionPolicy))
	}
	return result, nil
}

func encodeFeatureValue(v identity.FeatureValue) ([]byte, error) {
	switch v.Kind {
	case identity.FeatureText:
		return cborText(v.Text), nil
	case identity.FeatureBytes:
		return cborBytes(v.Bytes), nil
	case identity.FeatureUint64:
		return cborUint(v.Uint64), nil
	case identity.FeatureInt64:
		return cborInt(v.Int64), nil
	case identity.FeatureBool:
		if v.Bool {
			return []byte{0xf5}, nil
		}
		return []byte{0xf4}, nil
	case identity.FeatureTime:
		if !postgresExactTime(v.Time) {
			return nil, codecError()
		}
		return cborInt(v.Time.UnixMicro()), nil
	default:
		return nil, codecError()
	}
}
