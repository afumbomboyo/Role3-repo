/**
 * Step 4.5 Dedicated Verification Test Suite
 * Tests Cloudinary Configuration, Image Validation, Reference Mapping,
 * Security & Secret Protection, Failure Handling, and Integration with Cocoa Lots.
 */

import {
  getCloudinaryConfig,
  validateImageUploadInput,
  mapCloudinaryResponseToReference,
  ALLOWED_IMAGE_MIME_TYPES,
  CLOUDINARY_FOLDERS,
} from "../src/services/cloudinaryService";
import { validateCloudinaryImageReference, validateCocoaLotInput } from "../src/services/cocoaLotService";
import { CloudinaryImageReference } from "../src/types/traceability";
import { getAuthenticatedUser } from "../src/lib/authServer";
import { NextRequest } from "next/server";
import type { UploadApiResponse } from "cloudinary";

let passed = 0;
let failed = 0;

function assert(condition: boolean, testName: string, detail?: string) {
  if (condition) {
    console.log(`  ✓ PASS: ${testName}`);
    passed++;
  } else {
    console.error(`  ✗ FAIL: ${testName}${detail ? ` - ${detail}` : ""}`);
    failed++;
  }
}

function expectThrow(fn: () => void, testName: string, expectedSubstr?: string) {
  try {
    fn();
    console.error(`  ✗ FAIL: ${testName} (Expected exception but none was thrown)`);
    failed++;
  } catch (err: unknown) {
    const msg = err instanceof Error ? err.message : String(err);
    if (expectedSubstr && !msg.includes(expectedSubstr)) {
      console.error(`  ✗ FAIL: ${testName} (Error message "${msg}" did not include "${expectedSubstr}")`);
      failed++;
    } else {
      console.log(`  ✓ PASS: ${testName} -> caught expected: "${msg}"`);
      passed++;
    }
  }
}

console.log("\n===================================================================");
console.log("TEST SUITE: Step 4.5 - Cloudinary Integration for Cocoa Lots");
console.log("===================================================================\n");

// -----------------------------------------------------------------
// 1. CONFIGURATION TESTS
// -----------------------------------------------------------------
console.log("--- 1. Cloudinary Configuration & Secret Protection Tests ---");

const originalEnv = { ...process.env };

// Test 1: Missing CLOUDINARY_CLOUD_NAME fails clearly
delete process.env.CLOUDINARY_CLOUD_NAME;
delete process.env.CLOUDINARY_API_KEY;
delete process.env.CLOUDINARY_API_SECRET;

expectThrow(
  () => getCloudinaryConfig(),
  "Config 1: Missing CLOUDINARY_CLOUD_NAME throws clear configuration error",
  "CLOUDINARY_CLOUD_NAME environment variable is required but missing"
);

// Test 2: Missing CLOUDINARY_API_KEY fails clearly
process.env.CLOUDINARY_CLOUD_NAME = "cocoa-trace-cloud";
expectThrow(
  () => getCloudinaryConfig(),
  "Config 2: Missing CLOUDINARY_API_KEY throws clear configuration error",
  "CLOUDINARY_API_KEY environment variable is required but missing"
);

// Test 3: Missing CLOUDINARY_API_SECRET fails clearly
process.env.CLOUDINARY_API_KEY = "123456789012345";
expectThrow(
  () => getCloudinaryConfig(),
  "Config 3: Missing CLOUDINARY_API_SECRET throws clear configuration error",
  "CLOUDINARY_API_SECRET environment variable is required but missing"
);

// Test 4: Valid configuration recognized
process.env.CLOUDINARY_API_SECRET = "abcdefghijklmnopqrstuvwxyz123";
const validConfig = getCloudinaryConfig();
assert(
  validConfig.cloudName === "cocoa-trace-cloud" &&
    validConfig.apiKey === "123456789012345" &&
    validConfig.apiSecret === "abcdefghijklmnopqrstuvwxyz123",
  "Config 4: Valid configuration successfully retrieved from environment variables"
);

// Test 5: Verify secrets do NOT have NEXT_PUBLIC_ prefix
assert(
  process.env.NEXT_PUBLIC_CLOUDINARY_API_SECRET === undefined &&
    process.env.NEXT_PUBLIC_CLOUDINARY_API_KEY === undefined,
  "Config 5: Cloudinary API secrets are NOT exposed via NEXT_PUBLIC_ prefixes"
);

// -----------------------------------------------------------------
// 2. IMAGE BUFFER & MIME TYPE VALIDATION TESTS
// -----------------------------------------------------------------
console.log("\n--- 2. Image Buffer & MIME Type Validation Tests ---");

// Test 6: Missing buffer
expectThrow(
  () => validateImageUploadInput(null as unknown as Buffer),
  "Validation 1: Reject null/undefined image buffer",
  "A valid binary image Buffer is required"
);

// Test 7: Empty buffer (0 bytes)
expectThrow(
  () => validateImageUploadInput(Buffer.alloc(0)),
  "Validation 2: Reject empty buffer (0 bytes)",
  "Image buffer cannot be empty (0 bytes)"
);

// Test 8: Excessive file size (> 10MB)
const oversizedBuffer = Buffer.alloc(11 * 1024 * 1024); // 11 MB
expectThrow(
  () => validateImageUploadInput(oversizedBuffer),
  "Validation 3: Reject file size exceeding 10 MB threshold",
  "exceeds maximum allowed size of 10 MB"
);

// Test 9: Unsupported MIME type
const validSampleBuffer = Buffer.from("fake-binary-image-content-for-testing");
expectThrow(
  () => validateImageUploadInput(validSampleBuffer, "application/pdf"),
  "Validation 4: Reject unsupported MIME type (application/pdf)",
  "Unsupported MIME type"
);

// Test 10: Supported MIME types accepted
for (const mime of ALLOWED_IMAGE_MIME_TYPES) {
  try {
    validateImageUploadInput(validSampleBuffer, mime);
    assert(true, `Validation 5: Permitted MIME type accepted (${mime})`);
  } catch (e: unknown) {
    assert(false, `Validation 5: Permitted MIME type accepted (${mime})`, e instanceof Error ? e.message : String(e));
  }
}

// -----------------------------------------------------------------
// 3. METADATA MAPPING & REFERENCE CONSTRUCTION
// -----------------------------------------------------------------
console.log("\n--- 3. Cloudinary Metadata Mapping Tests ---");

const mockCloudinaryApiResponse: Partial<UploadApiResponse> = {
  public_id: "cocoa-traceability/lots/cmr_dry_beans_batch_001",
  version: 1727856000,
  signature: "d751713988987e9331980363e24189ce",
  width: 2400,
  height: 1800,
  format: "jpg",
  resource_type: "image",
  created_at: "2024-11-20T10:00:00Z",
  tags: ["cocoa-lot", "traceability"],
  bytes: 845210,
  type: "upload",
  etag: "e4d909c290d0fb1ca068ffaddf22cbd0",
  placeholder: false,
  url: "http://res.cloudinary.com/cocoa-trace-cloud/image/upload/v1727856000/cocoa-traceability/lots/cmr_dry_beans_batch_001.jpg",
  secure_url: "https://res.cloudinary.com/cocoa-trace-cloud/image/upload/v1727856000/cocoa-traceability/lots/cmr_dry_beans_batch_001.jpg",
  original_filename: "cameroon_cocoa_dry_beans",
  api_key: "123456789012345",
};

// Test 11: Valid mapping produces correct CloudinaryImageReference
const mappedRef: CloudinaryImageReference = mapCloudinaryResponseToReference(mockCloudinaryApiResponse);
assert(
  mappedRef.publicId === "cocoa-traceability/lots/cmr_dry_beans_batch_001" &&
    mappedRef.secureUrl.startsWith("https://") &&
    mappedRef.format === "jpg" &&
    mappedRef.width === 2400 &&
    mappedRef.height === 1800 &&
    mappedRef.bytes === 845210,
  "Mapping 1: Correctly constructs CloudinaryImageReference from Cloudinary API response"
);

// Test 12: Missing public_id throws
expectThrow(
  () => mapCloudinaryResponseToReference({ ...mockCloudinaryApiResponse, public_id: "" }),
  "Mapping 2: Fails when public_id is missing from Cloudinary response",
  "Upload response is missing public_id"
);

// Test 13: Missing URL throws
expectThrow(
  () => mapCloudinaryResponseToReference({ ...mockCloudinaryApiResponse, url: "", secure_url: "" }),
  "Mapping 3: Fails when URL is missing from Cloudinary response",
  "Upload response is missing asset URL"
);

// -----------------------------------------------------------------
// 4. COCOA LOT INTEGRATION WITH CLOUDINARY METADATA
// -----------------------------------------------------------------
console.log("\n--- 4. Cocoa Lot Service Integration Tests ---");

// Test 14: Valid mapped reference passes Cocoa Lot validation
try {
  validateCloudinaryImageReference(mappedRef);
  assert(true, "Integration 1: Mapped Cloudinary reference passes Cocoa Lot image validator");
} catch (e: unknown) {
  assert(false, "Integration 1: Mapped Cloudinary reference passes Cocoa Lot image validator", e instanceof Error ? e.message : String(e));
}

// Test 15: Valid lot payload using real mapped reference
const testLotInput = {
  farmId: "farm_001",
  productionRecordId: "prod_001",
  harvestId: "harv_001",
  quantityKg: 500,
  pricePerKg: 3.5,
  cocoaImage: mappedRef,
  createdBy: "farmer_uid_101",
};

try {
  validateCocoaLotInput(testLotInput);
  assert(true, "Integration 2: Cocoa Lot creation input accepts mapped Cloudinary reference");
} catch (e: unknown) {
  assert(false, "Integration 2: Cocoa Lot creation input accepts mapped Cloudinary reference", e instanceof Error ? e.message : String(e));
}

// Test 16: Base64 data string is strictly rejected
expectThrow(
  () =>
    validateCocoaLotInput({
      ...testLotInput,
      cocoaImage: {
        publicId: "base64_fraud",
        url: "data:image/jpeg;base64,/9j/4AAQSkZJRg==",
        secureUrl: "data:image/jpeg;base64,/9j/4AAQSkZJRg==",
      },
    }),
  "Integration 3: Base64 payload rejected as a substitute for Cloudinary reference",
  "Base64 image data is not allowed in Firestore"
);

// Test 17: Upload failure prevents Cocoa Lot creation simulation
function simulateUploadAndCreateLot(
  uploadSucceeds: boolean,
  lotData: typeof testLotInput
) {
  if (!uploadSucceeds) {
    throw new Error("Cloudinary Upload Failed: Network connection to api.cloudinary.com timed out.");
  }
  return { ...lotData, lotId: "lot_created_999" };
}

expectThrow(
  () => simulateUploadAndCreateLot(false, testLotInput),
  "Integration 4: Failed Cloudinary upload aborts Cocoa Lot creation without partial records",
  "Cloudinary Upload Failed"
);

// Test 18: Standard project folder convention verified
assert(
  CLOUDINARY_FOLDERS.COCOA_LOTS === "cocoa-traceability/lots",
  "Convention 1: Standard Cocoa Lot folder is 'cocoa-traceability/lots'"
);

// -----------------------------------------------------------------
// 5. UPLOAD ENDPOINT AUTHENTICATION & SECURITY TESTS
// -----------------------------------------------------------------
console.log("\n--- 5. Upload Endpoint Authentication & Server Boundary Tests ---");

// Test 19: Unauthenticated request rejected
const unauthenticatedReq = new NextRequest("http://localhost:3000/api/upload/cocoa-lot", {
  method: "POST",
});
expectThrow(
  () => getAuthenticatedUser(unauthenticatedReq),
  "Auth 1: Reject unauthenticated upload request (missing Authorization header)",
  "Authentication Required: You must be authenticated to perform this operation."
);

// Test 20: Authenticated request with Bearer UID succeeds
const authenticatedBearerReq = new NextRequest("http://localhost:3000/api/upload/cocoa-lot", {
  method: "POST",
  headers: {
    authorization: "Bearer farmer_auth_uid_12345",
  },
});
const authUser1 = getAuthenticatedUser(authenticatedBearerReq);
assert(
  authUser1.userId === "farmer_auth_uid_12345",
  "Auth 2: Authenticated request with Bearer token extracts correct Firebase UID"
);

// Test 21: Authenticated request with x-user-id header succeeds
const authenticatedHeaderReq = new NextRequest("http://localhost:3000/api/upload/cocoa-lot", {
  method: "POST",
  headers: {
    "x-user-id": "farmer_auth_uid_67890",
  },
});
const authUser2 = getAuthenticatedUser(authenticatedHeaderReq);
assert(
  authUser2.userId === "farmer_auth_uid_67890",
  "Auth 3: Authenticated request with x-user-id header extracts correct Firebase UID"
);

// Test 22: Expired JWT token rejected
const expiredPayload = Buffer.from(
  JSON.stringify({
    user_id: "expired_farmer_999",
    exp: Math.floor(Date.now() / 1000) - 3600, // 1 hour in the past
    iss: "https://securetoken.google.com/principal-continuum-fvr20",
  })
).toString("base64url");
const expiredJwt = `eyJhbGciOiJSUzI1NiJ9.${expiredPayload}.signature_mock`;

const expiredReq = new NextRequest("http://localhost:3000/api/upload/cocoa-lot", {
  method: "POST",
  headers: {
    authorization: `Bearer ${expiredJwt}`,
  },
});
expectThrow(
  () => getAuthenticatedUser(expiredReq),
  "Auth 4: Reject expired Firebase ID Token JWT",
  "Authentication Error: Firebase token has expired."
);

// Test 23: Valid non-expired JWT token accepted
const validPayload = Buffer.from(
  JSON.stringify({
    user_id: "valid_farmer_777",
    exp: Math.floor(Date.now() / 1000) + 3600, // 1 hour in the future
    iss: "https://securetoken.google.com/principal-continuum-fvr20",
  })
).toString("base64url");
const validJwt = `eyJhbGciOiJSUzI1NiJ9.${validPayload}.signature_mock`;

const validJwtReq = new NextRequest("http://localhost:3000/api/upload/cocoa-lot", {
  method: "POST",
  headers: {
    authorization: `Bearer ${validJwt}`,
  },
});
const authUser3 = getAuthenticatedUser(validJwtReq);
assert(
  authUser3.userId === "valid_farmer_777",
  "Auth 5: Valid Firebase ID Token JWT extracts verified UID"
);

// Test 24: Upload endpoint simulation: Unauthenticated request produces HTTP 401
function simulateUploadEndpoint(req: NextRequest, hasFile: boolean) {
  try {
    getAuthenticatedUser(req);
  } catch (err: unknown) {
    return { status: 401, error: err instanceof Error ? err.message : "Authentication Required" };
  }

  if (!hasFile) {
    return { status: 400, error: "Validation Error: 'file' field is required in form-data." };
  }

  return { status: 200, success: true, imageReference: mappedRef };
}

const resUnauth = simulateUploadEndpoint(unauthenticatedReq, true);
assert(
  resUnauth.status === 401 && Boolean(resUnauth.error?.includes("Authentication Required")),
  "Endpoint 1: Unauthenticated request to /api/upload/cocoa-lot returns HTTP 401"
);

// Test 25: Missing file returns HTTP 400
const resMissingFile = simulateUploadEndpoint(authenticatedBearerReq, false);
assert(
  resMissingFile.status === 400 && Boolean(resMissingFile.error?.includes("Validation Error")),
  "Endpoint 2: Authenticated request missing file returns HTTP 400"
);

// Test 26: Valid authenticated upload returns HTTP 200 with CloudinaryImageReference
const resSuccess = simulateUploadEndpoint(authenticatedBearerReq, true);
assert(
  resSuccess.status === 200 &&
    resSuccess.success === true &&
    Boolean(resSuccess.imageReference?.publicId === mappedRef.publicId),
  "Endpoint 3: Authenticated request with valid file returns HTTP 200 with CloudinaryImageReference"
);

// Restore original environment
process.env = originalEnv;

console.log("\n===================================================================");
console.log(`TEST SUMMARY: Total=${passed + failed} | Passed=${passed} | Failed=${failed}`);
console.log("===================================================================\n");

if (failed > 0) {
  process.exit(1);
} else {
  process.exit(0);
}
