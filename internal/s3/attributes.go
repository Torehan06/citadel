package s3

import (
	"encoding/xml"
	"net/http"
	"strconv"
	"strings"
)

// GetObjectAttributes and GetObject ?partNumber=N: both expose the part
// structure recorded in a multipart object's manifest.
// https://docs.aws.amazon.com/AmazonS3/latest/API/API_GetObjectAttributes.html

// partNumbers returns the manifest with part numbers filled in (manifests
// written before numbers were recorded are numbered 1..n).
func (o *objectRow) partNumbers() []partRef {
	out := make([]partRef, len(o.Parts))
	for i, p := range o.Parts {
		if p.Number == 0 {
			p.Number = i + 1
		}
		out[i] = p
	}
	return out
}

// partRange resolves ?partNumber=N to a byte range of the object.
// A single-part object has exactly one part, the whole object.
func partRange(o *objectRow, n int) (start, length int64, count int, err error) {
	if len(o.Parts) == 0 {
		if n != 1 {
			return 0, 0, 0, errf(400, "InvalidPart", "The requested partnumber is not satisfiable")
		}
		return 0, o.Size, 1, nil
	}
	var off int64
	for _, p := range o.partNumbers() {
		if p.Number == n {
			return off, p.Size, len(o.Parts), nil
		}
		off += p.Size
	}
	return 0, 0, 0, errf(400, "InvalidPart", "The requested partnumber is not satisfiable")
}

// partChecksum is the checksum recorded for part n, for composite objects.
func (o *objectRow) partChecksum(n int) string {
	for _, p := range o.partNumbers() {
		if p.Number == n {
			return p.Checksum
		}
	}
	return ""
}

type attrChecksum struct {
	ChecksumCRC32     string `xml:"ChecksumCRC32,omitempty"`
	ChecksumCRC32C    string `xml:"ChecksumCRC32C,omitempty"`
	ChecksumCRC64NVME string `xml:"ChecksumCRC64NVME,omitempty"`
	ChecksumSHA1      string `xml:"ChecksumSHA1,omitempty"`
	ChecksumSHA256    string `xml:"ChecksumSHA256,omitempty"`
	ChecksumType      string `xml:"ChecksumType,omitempty"`
}

func (c *attrChecksum) set(algo, v string) {
	switch algo {
	case "CRC32":
		c.ChecksumCRC32 = v
	case "CRC32C":
		c.ChecksumCRC32C = v
	case "CRC64NVME":
		c.ChecksumCRC64NVME = v
	case "SHA1":
		c.ChecksumSHA1 = v
	case "SHA256":
		c.ChecksumSHA256 = v
	}
}

type attrPart struct {
	PartNumber int   `xml:"PartNumber"`
	Size       int64 `xml:"Size"`
	attrChecksum
}

type attrParts struct {
	TotalPartsCount      int        `xml:"PartsCount"` // TotalPartsCount in the SDKs
	PartNumberMarker     int        `xml:"PartNumberMarker"`
	NextPartNumberMarker int        `xml:"NextPartNumberMarker"`
	MaxParts             int        `xml:"MaxParts"`
	IsTruncated          bool       `xml:"IsTruncated"`
	Parts                []attrPart `xml:"Part"`
}

type objectAttributes struct {
	XMLName      xml.Name      `xml:"http://s3.amazonaws.com/doc/2006-03-01/ GetObjectAttributesResponse"`
	ETag         string        `xml:"ETag,omitempty"`
	Checksum     *attrChecksum `xml:"Checksum,omitempty"`
	ObjectParts  *attrParts    `xml:"ObjectParts,omitempty"`
	StorageClass string        `xml:"StorageClass,omitempty"`
	ObjectSize   *int64        `xml:"ObjectSize,omitempty"`
}

func (h *Handler) getObjectAttributes(req *request) error {
	b, o, err := h.objectForRead(req, "s3:GetObjectAttributes", permRead)
	if err != nil {
		return err
	}
	want := map[string]bool{}
	for _, v := range req.r.Header.Values("X-Amz-Object-Attributes") {
		for _, a := range strings.Split(v, ",") {
			want[strings.TrimSpace(a)] = true
		}
	}
	if len(want) == 0 {
		return errInvalidArgument("Minimum of one object attribute must be specified.")
	}
	maxParts := 1000
	if s := req.r.Header.Get("X-Amz-Max-Parts"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return errInvalidArgument("Provided max-parts not an integer or within integer range")
		}
		maxParts = min(n, 1000)
	}
	marker := 0
	if s := req.r.Header.Get("X-Amz-Part-Number-Marker"); s != "" {
		n, err := strconv.Atoi(s)
		if err != nil || n < 0 {
			return errInvalidArgument("Provided part-number-marker not an integer or within integer range")
		}
		marker = n
	}

	var res objectAttributes
	if want["ETag"] {
		res.ETag = strings.Trim(o.ETag, `"`)
	}
	if want["Checksum"] && o.Meta.ChecksumAlgo != "" {
		c := &attrChecksum{ChecksumType: o.Meta.ChecksumType}
		if c.ChecksumType == "" {
			c.ChecksumType = "FULL_OBJECT"
		}
		c.set(o.Meta.ChecksumAlgo, o.Meta.Checksum)
		res.Checksum = c
	}
	if want["ObjectParts"] && len(o.Parts) > 0 {
		op := &attrParts{TotalPartsCount: len(o.Parts), PartNumberMarker: marker, MaxParts: maxParts}
		for _, p := range o.partNumbers() {
			if p.Number <= marker {
				continue
			}
			if len(op.Parts) == maxParts {
				op.IsTruncated = true
				break
			}
			ap := attrPart{PartNumber: p.Number, Size: p.Size}
			if o.Meta.ChecksumType == "COMPOSITE" && p.Checksum != "" {
				ap.set(o.Meta.ChecksumAlgo, p.Checksum)
			}
			op.Parts = append(op.Parts, ap)
			op.NextPartNumberMarker = p.Number
		}
		res.ObjectParts = op
	}
	if want["StorageClass"] {
		res.StorageClass = storageClass(*o)
	}
	if want["ObjectSize"] {
		size := o.Size
		res.ObjectSize = &size
	}
	req.w.Header().Set("Last-Modified", o.LastModified.Format(http.TimeFormat))
	if b.Versioning != "" {
		req.w.Header().Set("x-amz-version-id", o.VersionID)
	}
	writeXML(req.w, http.StatusOK, res)
	return nil
}
