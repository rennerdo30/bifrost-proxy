import { defineCollection } from "astro:content";
import { docsLoader } from "@astrojs/starlight/loaders";
import { docsSchema } from "@astrojs/starlight/schema";

export const collections = {
  // Starlight 0.41 / Astro 7 removed implicit content-directory collections, so
  // the loader has to be declared explicitly.
  docs: defineCollection({ loader: docsLoader(), schema: docsSchema() }),
};
