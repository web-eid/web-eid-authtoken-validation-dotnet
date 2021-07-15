namespace WebEid.Security.Tests.Util
{
    using System.Globalization;
    using System.Text;

    public static class TitleCaseExtension
    {
        public static string ToTitleCase(this string input)
        {
            var titleCase = new StringBuilder(input.Length);
            var nextTitleCase = true;

            foreach (var c in input.ToLower(CultureInfo.CurrentCulture))
            {
                var mutableChar = c;
                if (!char.IsLetterOrDigit(c))
                {
                    nextTitleCase = true;
                }
                else if (nextTitleCase)
                {
                    mutableChar = char.ToUpper(c, CultureInfo.CurrentCulture);
                    nextTitleCase = false;
                }
                titleCase.Append(mutableChar);
            }

            return titleCase.ToString();
        }
    }
}
