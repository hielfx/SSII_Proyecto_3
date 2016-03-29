__author__ = 'Daniel Sánchez'

#encoding:utf-8

import matplotlib.pyplot as plt
import sqlite3
import logging
import traceback
import datetime
import os


def main_chart(show=False):
    """show can be True or False. False by default.
    If show = True, the system display the chart in a interactive mode.
    If show = False, it will save the chart in *.png format"""

    app_name="socket_app_py"

    # Logger configuration
    logger = logging.getLogger(app_name)
    logger.setLevel(logging.DEBUG)

    # create file handler which logs even debug messages
    fh = logging.FileHandler('chart.log')
    fh.setLevel(logging.DEBUG)

    # create console handler with a higher log level
    ch = logging.StreamHandler()
    ch.setLevel(logging.ERROR)

    # create formatter and add it to the handlers
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    # add the handlers to the logger
    logger.addHandler(fh)
    logger.addHandler(ch)

    def generate_error_message(msg):
        logger.info(str(msg) + "\n\n")
        # traceback.print_exc()
        logger.debug(str(traceback.format_exc()) + "\n\n")

    conn = sqlite3.connect(app_name+".db")

    ratio_cursor = None
    ratio_name = "transmission"

    logger.info("Starting process to plot the ratios")
    try:
        logger.info("Checking out the ratios...")
        _check_table = "SELECT * FROM sqlite_master WHERE name ='{0}' and type='table';".format(ratio_name)
        ratio_cursor = conn.execute(_check_table)

        x = []  # The values of the x axis. We want this to be numbers
        y = []  # The values of the y axis. The ratio
        x_sticks = []  # The text we display in the x axis. The days
        x_sticks_aux = []
        count = 0

        if (ratio_cursor is not None
            and ratio_cursor.fetchone() is not None):

            logger.info("Processing the ratios...")

            # We use this statement to get the insert_date (formatted) and the ratio of the days of the previous month.
            _get_ratios = "select strftime('%Y-%m-%d',insert_date), round(avg(integrity),2) from transmission where strftime('%Y-%m',insert_date)=strftime('%Y-%m',date('now','start of month','-1 month')) group by strftime('%Y-%m-%d',insert_date);"
            ratio_cursor.execute(_get_ratios)

            # We append the values to their lists
            for row in ratio_cursor:
                x.append(count)
                y.append(row[1])
                x_sticks.append(row[0])
                x_sticks_aux.append(row[0].split("-")[2])  # To display only the day
                count += 1  # We need this variable to display correctly the x axis with the text

            logger.info("Generating axis for the chart...")
            plt.axis([-0.1, count, -0.1, 1.1])  # The axis of the chart ([xmin,xmax,ymin,ymax]). We used those values for a clear vision of the chart
            plt.xticks(x, x_sticks_aux)  # We append the text to the x axis

            logger.info("Adding the ratios to the chart...")
            # We want to print lines with the dots so we have to do this:
            plt.plot(x, y, 'ro')  # We print the red dots
            plt.plot(x, y, 'r')  # We print the red lines

            logger.info("Labeling the axis...")
            # We label the axis
            plt.ylabel('Ratio')  # The y label
            plt.xlabel('Day')  # The x label

            logger.info("Adding title...")
            # Adding a title
            _from = x_sticks[0].split('-')
            plt.title("Ratios from {0}-{1} \n".format(_from[0], _from[1]))


             # If show = True, we plot the chart and show it as an interactive mode
            if show:
                logger.info("Selected show chart")
                logger.info("Generating the chart in interactive mode...")
                plt.show()
            else:
                logger.info("Selected save chart")
                logger.info("Generating and saving the chart...")
                # Saving the chart to a *.png file
                name = str(datetime.datetime.now().strftime("%Y-%m-%d %H.%M.%S"))+" - Ratio chart.png"
                plt.savefig(name, bbox_inches='tight')

                logger.info("Chart created with name '{0}'\n\n".format(name))


        else:
            logger.info("Unable to generate the chart, there are no ratios yet\n")

    except Exception:
        generate_error_message("An error occurred while checking the ratios")

if __name__ == "__main__":
    main_chart()