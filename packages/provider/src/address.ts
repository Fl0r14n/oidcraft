/** IPv6 counts by its /64: one subscriber is routinely given a whole one, so by address a guesser has 2^64 of them (G-9). */
export const addressBucket = (ip: string) => {
  if (!ip.includes(':')) return ip
  const written = ip
    .toLowerCase()
    .replace(/^\[|\]$/g, '')
    .split('%')[0] as string
  const dotted = /^(.*:)(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(written)
  const [, lead = '', a = 0, b = 0, c = 0, d = 0] = dotted ?? []
  const address = dotted ? `${lead}${((+a << 8) | +b).toString(16)}:${((+c << 8) | +d).toString(16)}` : written
  const [head = '', tail] = address.split('::')
  const left = head ? head.split(':') : []
  const right = tail ? tail.split(':') : []
  const groups = tail === undefined ? left : [...left, ...Array<string>(Math.max(0, 8 - left.length - right.length)).fill('0'), ...right]
  const words = groups.map(group => Number.parseInt(group || '0', 16))
  const [w0, w1, w2, w3, w4, w5, w6 = 0, w7 = 0] = words
  // G-9: an IPv4 peer reached through a mapped address or a NAT64/SIIT translator (RFC 6052 §2.1) counts by its own address, not the translator's /64.
  if ((!w0 && !w1 && !w2 && !w3 && !w4 && w5 === 0xffff) || (w0 === 0x64 && w1 === 0xff9b && !w2 && !w3 && !w4 && !w5)) {
    return [w6 >> 8, w6 & 255, w7 >> 8, w7 & 255].join('.')
  }
  return `${words
    .slice(0, 4)
    .map(word => word.toString(16))
    .join(':')}::/64`
}
