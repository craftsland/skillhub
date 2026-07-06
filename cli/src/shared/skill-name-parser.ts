export interface ParsedSkillName {
  namespace: string
  slug: string
}

export function parseSkillName(skillName: string, defaultNamespace = 'global'): ParsedSkillName {
  const separatorIndex = skillName.indexOf('--')
  const trailingSeparatorIndex = skillName.lastIndexOf('--')

  if (separatorIndex <= 0) {
    return {
      namespace: defaultNamespace,
      slug: separatorIndex === 0 ? skillName.slice(2) : skillName
    }
  }

  if (trailingSeparatorIndex === separatorIndex && trailingSeparatorIndex + 2 === skillName.length) {
    return {
      namespace: defaultNamespace,
      slug: skillName.slice(0, -2)
    }
  }

  return {
    namespace: skillName.slice(0, separatorIndex),
    slug: skillName.slice(separatorIndex + 2)
  }
}
