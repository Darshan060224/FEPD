# Evidence Type Selection - Visual Workflow

## UI Flow Diagram

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        FEPD Case Creation Dialog                         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
          ┌─────────────────────────────────────────────────┐
          │  Evidence Type Selection                        │
          │  ┌───────────────────────────────────────────┐  │
          │  │ ☐ Multi-part forensic image              │  │
          │  └───────────────────────────────────────────┘  │
          └─────────────────────────────────────────────────┘
                      │                    │
         UNCHECKED ◄──┘                    └──► CHECKED
              │                                     │
              ▼                                     ▼
    ┌─────────────────────┐              ┌──────────────────────┐
    │  SINGLE FILE MODE   │              │  MULTI-PART MODE     │
    └─────────────────────┘              └──────────────────────┘
              │                                     │
              ▼                                     ▼
    ┌─────────────────────┐              ┌──────────────────────┐
    │ Browse File (1 only)│              │ Browse Files (multi) │
    └─────────────────────┘              └──────────────────────┘
              │                                     │
              ▼                                     ▼
    ┌─────────────────────┐              ┌──────────────────────┐
    │ Select 1 file       │              │ Select all parts     │
    │ (.img, .dd, .mem)   │              │ (E01, E02, E03...)   │
    └─────────────────────┘              └──────────────────────┘
              │                                     │
              │                                     ▼
              │                          ┌──────────────────────┐
              │                          │ Detect Pattern       │
              │                          │ (E01, L01, 001)      │
              │                          └──────────────────────┘
              │                                     │
              │                                     ▼
              │                          ┌──────────────────────┐
              │                          │ Validate Sequence    │
              │                          │ (continuous? gaps?)  │
              │                          └──────────────────────┘
              │                                     │
              │                          ┌──────────┴──────────┐
              │                          │                     │
              │                     COMPLETE              INCOMPLETE
              │                          │                     │
              │                          ▼                     ▼
              │                   ┌─────────────┐      ┌─────────────┐
              │                   │  ✓ Valid    │      │ ❌ Error    │
              │                   │  Evidence   │      │ Missing: E05│
              │                   └─────────────┘      └─────────────┘
              │                          │
              └──────────────────────────┴───────────────────┐
                                                              │
                                                              ▼
                                                   ┌──────────────────┐
                                                   │ Create Evidence  │
                                                   │ Object           │
                                                   └──────────────────┘
                                                              │
                                                              ▼
                                                   ┌──────────────────┐
                                                   │ Store in Case    │
                                                   │ Metadata         │
                                                   └──────────────────┘
```

---

## Validation Logic Flow

```
┌─────────────────────────────────────────────────────────────┐
│                     validate_evidence()                      │
│                                                               │
│  Input: file_paths[], is_multipart_mode                     │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                    ┌───────────────┐
                    │ Check Mode    │
                    └───────────────┘
                            │
            ┌───────────────┴───────────────┐
            │                               │
        SINGLE                          MULTI-PART
            │                               │
            ▼                               ▼
    ┌──────────────┐              ┌──────────────────┐
    │ len(files)=1?│              │ Detect Pattern?  │
    └──────────────┘              └──────────────────┘
         │     │                        │          │
        YES    NO                      YES         NO
         │     │                        │          │
         │     └───► ERROR              │          └───► ERROR
         │           "Multiple          │                "No pattern"
         │            files"            │
         ▼                              ▼
    ┌──────────────┐         ┌──────────────────────┐
    │ Valid format?│         │ Group by base name   │
    │ (.img, .dd)  │         │ Extract sequences    │
    └──────────────┘         └──────────────────────┘
         │     │                        │
        YES    NO                       ▼
         │     │              ┌──────────────────────┐
         │     └───► ERROR    │ Validate Sequence    │
         │           "Bad     │ (continuous? start?) │
         │            format" └──────────────────────┘
         │                           │          │
         │                          YES         NO
         │                           │          │
         │                           │          └───► ERROR
         │                           │                "Missing: E05"
         │                           │
         └───────────────────────────┴─────────────────┐
                                                        │
                                                        ▼
                                          ┌──────────────────────┐
                                          │ Create EvidenceObject│
                                          └──────────────────────┘
                                                        │
                                                        ▼
                                          ┌──────────────────────┐
                                          │ Return (True, obj, "")│
                                          └──────────────────────┘
```

---

## Backend Processing Flow

```
┌─────────────────────────────────────────────────────────────┐
│                      Case Creation                           │
└─────────────────────────────────────────────────────────────┘
                            │
                            ▼
                ┌──────────────────────┐
                │ Evidence Object      │
                │ Type: MULTI_PART     │
                │ Parts: [E01...E09]   │
                └──────────────────────┘
                            │
                            ▼
           ┌────────────────┴────────────────┐
           │                                 │
           ▼                                 ▼
   ┌──────────────┐                 ┌──────────────┐
   │ Hash Primary │                 │ Copy All     │
   │ (E01 only)   │                 │ Parts to     │
   └──────────────┘                 │ Case Dir     │
           │                         └──────────────┘
           │                                 │
           ▼                                 ▼
   ┌──────────────┐                 ┌──────────────┐
   │ Create Case  │                 │ Store        │
   │ Metadata     │                 │ Evidence     │
   │ + Evidence   │                 │ Metadata     │
   │   Object     │                 │              │
   └──────────────┘                 └──────────────┘
           │                                 │
           └────────────────┬────────────────┘
                            │
                            ▼
                ┌──────────────────────┐
                │ FEPD OS Mount        │
                │                      │
                │ Mounts: E01          │
                │ Reads: E02-E09       │
                │ Exposes: Virtual Disk│
                └──────────────────────┘
                            │
                            ▼
                ┌──────────────────────┐
                │ Analyst sees:        │
                │ /volumes/system      │
                │ /volumes/data        │
                │                      │
                │ (No individual parts)│
                └──────────────────────┘
```

---

## Data Model

```
EvidenceObject
├── id: "LoneWolf"
├── type: "multi_part_disk"
├── format: "E01_MULTI"
├── parts: [
│   ├── EvidenceSegment {
│   │   ├── path: "LoneWolf.E01"
│   │   ├── sequence_number: 1
│   │   ├── extension: ".E01"
│   │   └── size_bytes: 2147483648
│   │   }
│   ├── EvidenceSegment {
│   │   ├── path: "LoneWolf.E02"
│   │   ├── sequence_number: 2
│   │   └── ...
│   │   }
│   └── ... (E03-E09)
│   ]
├── base_name: "LoneWolf"
├── total_parts: 9
├── total_size_bytes: 15663104000
├── is_complete: True
├── missing_parts: []
└── integrity_verified: False

Methods:
├── get_primary_path() → LoneWolf.E01
├── get_all_paths() → [E01, E02, ... E09]
└── to_dict() → JSON serializable dict
```

---

## Error Handling Decision Tree

```
                        User Action
                             │
                             ▼
                    ┌────────────────┐
                    │ Select Files   │
                    └────────────────┘
                             │
                ┌────────────┴────────────┐
                │                         │
          Single Mode                Multi-Part Mode
                │                         │
                ▼                         ▼
        ┌───────────────┐         ┌──────────────┐
        │ Count = 1?    │         │ Pattern OK?  │
        └───────────────┘         └──────────────┘
            │       │                  │       │
           YES      NO                YES      NO
            │       │                  │       │
            │       └──► Error 1       │       └──► Error 3
            │           "Multiple      │           "No pattern"
            │            files"        │
            ▼                          ▼
        ┌───────────────┐         ┌──────────────┐
        │ Format OK?    │         │ Sequence OK? │
        └───────────────┘         └──────────────┘
            │       │                  │       │
           YES      NO                YES      NO
            │       │                  │       │
            │       └──► Error 2       │       └──► Error 4
            │           "Bad format"   │           "Missing: X"
            │                          │
            └──────────────────────────┴──► Success
                                             Create Case

Error Messages:
───────────────
Error 1: "You selected multiple files. Enable multi-part mode."
Error 2: "Unsupported format: .xyz. Allowed: .img, .dd, ..."
Error 3: "Could not detect multi-part pattern. Expected: E01, L01, 001"
Error 4: "Incomplete evidence set. Missing: LoneWolf.E05"
```

---

## File Storage Structure

```
cases/
└── LoneWolf_Case/
    ├── metadata/
    │   ├── case.json
    │   └── evidence.json ◄─── Evidence Object stored here
    │       {
    │         "id": "LoneWolf",
    │         "type": "multi_part_disk",
    │         "format": "E01_MULTI",
    │         "parts": [
    │           {"path": "evidence/LoneWolf.E01", "sequence": 1},
    │           {"path": "evidence/LoneWolf.E02", "sequence": 2},
    │           ...
    │         ],
    │         "total_parts": 9,
    │         "is_complete": true
    │       }
    ├── evidence/
    │   ├── LoneWolf.E01 ◄─── Primary (mounted)
    │   ├── LoneWolf.E02
    │   ├── LoneWolf.E03
    │   ├── ...
    │   └── LoneWolf.E09
    └── analysis/
        └── ...
```

---

## State Machine

```
                    ┌─────────────┐
                    │   INITIAL   │
                    └─────────────┘
                          │
                          ▼
                ┌───────────────────┐
                │ AWAITING_SELECTION│
                └───────────────────┘
                          │
              ┌───────────┴───────────┐
              │                       │
         Single Mode             Multi-Part Mode
              │                       │
              ▼                       ▼
      ┌──────────────┐        ┌──────────────┐
      │ VALIDATING   │        │ DETECTING    │
      │ SINGLE FILE  │        │ PATTERN      │
      └──────────────┘        └──────────────┘
              │                       │
              │                       ▼
              │               ┌──────────────┐
              │               │ VALIDATING   │
              │               │ SEQUENCE     │
              │               └──────────────┘
              │                       │
              └───────────┬───────────┘
                          │
                ┌─────────┴─────────┐
                │                   │
              VALID             INVALID
                │                   │
                ▼                   ▼
        ┌──────────────┐    ┌──────────────┐
        │   READY      │    │   ERROR      │
        │ (can create) │    │ (show error) │
        └──────────────┘    └──────────────┘
                │                   │
                ▼                   │
        ┌──────────────┐            │
        │  CREATING    │            │
        │  CASE        │            │
        └──────────────┘            │
                │                   │
                ▼                   │
        ┌──────────────┐            │
        │   COMPLETE   │            │
        └──────────────┘            │
                │                   │
                └───────────────────┘
                          │
                          ▼
                   ┌──────────────┐
                   │    RESET     │
                   └──────────────┘
```

---

This visual guide shows the complete workflow from UI interaction to backend storage.
