import { MongoClient } from "mongodb";

let clientPromise;
let indexesPromise;
let memoryDb;

function matches(document, query) {
  return Object.entries(query).every(([key, value]) => document?.[key] === value);
}

function setNested(document, path, value) {
  const parts = path.split(".");
  let target = document;
  for (const part of parts.slice(0, -1)) {
    target[part] ||= {};
    target = target[part];
  }
  target[parts.at(-1)] = value;
}

function memoryCollection(name, documents) {
  return {
    isMemory: true,

    async createIndex() {
      return `${name}_memory_index`;
    },

    async findOne(query) {
      return documents.find((document) => matches(document, query)) || null;
    },

    async allDocuments() {
      return structuredClone(documents);
    },

    async insertOne(document) {
      if (name === "reports" && documents.some((existing) =>
        existing.canonicalUrl === document.canonicalUrl &&
        existing.reporterId === document.reporterId)) {
        const error = new Error("Duplicate report");
        error.code = 11000;
        throw error;
      }
      documents.push(structuredClone(document));
      return { acknowledged: true };
    },

    async updateOne(query, update, options = {}) {
      let document = documents.find((entry) => matches(entry, query));
      const inserted = !document;
      if (!document) {
        if (!options.upsert) return { matchedCount: 0, modifiedCount: 0 };
        document = { ...query };
        documents.push(document);
      }

      if (inserted && update.$setOnInsert) Object.assign(document, update.$setOnInsert);
      if (update.$set) Object.assign(document, update.$set);
      for (const [path, amount] of Object.entries(update.$inc || {})) {
        const parts = path.split(".");
        let current = document;
        for (const part of parts) current = current?.[part];
        setNested(document, path, (current || 0) + amount);
      }
      return { matchedCount: inserted ? 0 : 1, modifiedCount: 1, upsertedCount: inserted ? 1 : 0 };
    }
  };
}

function getMemoryDb() {
  if (memoryDb) return memoryDb;
  const stores = new Map();
  memoryDb = {
    isMemory: true,
    collection(name) {
      if (!stores.has(name)) stores.set(name, []);
      return memoryCollection(name, stores.get(name));
    }
  };
  return memoryDb;
}

export async function getDb() {
  const uri = process.env.MONGODB_URI;
  if (!uri) return getMemoryDb();

  if (!clientPromise) {
    const client = new MongoClient(uri, {
      maxPoolSize: 10,
      serverSelectionTimeoutMS: 5000
    });
    clientPromise = client.connect();
  }

  const client = await clientPromise;
  const db = client.db(process.env.MONGODB_DB || "safeyou");

  if (!indexesPromise) {
    indexesPromise = Promise.all([
      db.collection("reputations").createIndex({ canonicalUrl: 1 }, { unique: true }),
      db.collection("reputations").createIndex({ hostname: 1 }),
      db.collection("reports").createIndex(
        { canonicalUrl: 1, reporterId: 1 },
        { unique: true }
      )
    ]).catch((error) => {
      indexesPromise = undefined;
      throw error;
    });
  }
  await indexesPromise;

  return db;
}
